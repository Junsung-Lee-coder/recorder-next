from __future__ import annotations

import base64
import hashlib
import json
import threading
from dataclasses import asdict
from typing import Any, Mapping
from urllib.parse import parse_qs, unquote, urlsplit

from .adapters import (
    ASRProvider,
    DeterministicRouter,
    HermesGateway,
    RouterAdapter,
    StaticASRProvider,
    StaticTTSProvider,
    TrustedScheduleCreateAdapter,
    TTSProvider,
)
from .canonical import hermes_content_hash, normalize_hermes_text
from .errors import NotFoundError, RecorderError, UnauthorizedError, ValidationError
from .models import AsrResult, HermesResult, RouterDecision, TTSResult
from .store import DEFAULT_MISSING_PAGE_SIZE, MAX_MISSING_PAGE_SIZE, FINAL_ERROR_MESSAGES, RecorderStore


class RecorderService:
    """Application service coordinating adapters around RecorderStore."""

    def __init__(
        self,
        store: RecorderStore,
        *,
        router: RouterAdapter | None = None,
        hermes: HermesGateway | None = None,
        asr_providers: Mapping[str, ASRProvider] | None = None,
        tts: TTSProvider | None = None,
        hermes_max_attempts: int = 2,
        hermes_grace_seconds: int = 30,
    ):
        self.store = store
        self.router = router or DeterministicRouter()
        self.hermes = hermes
        self.asr_providers = dict(asr_providers or {})
        self.tts = tts or StaticTTSProvider()
        self.schedule_adapter = TrustedScheduleCreateAdapter(store)
        self.hermes_max_attempts = max(1, hermes_max_attempts)
        self.hermes_grace_seconds = max(0, hermes_grace_seconds)
        self._lock = threading.RLock()

    def route_next(self, user_id: str, owner: str = "router-1") -> dict[str, Any] | None:
        claim = self.store.claim_router(user_id, owner)
        if claim is None:
            return None
        turn = claim["turn"]
        projects = self.store.list_projects(user_id)
        try:
            decision = self.router.decide(turn, projects)
        except Exception:
            return self.store.commit_routing_error(turn["turn_id"], owner=owner)
        if decision is None and not turn.get("current_project_number") and not projects:
            auto = self.store.create_project(
                user_id,
                project_number=f"AUTO-{int(turn['accepted_seq']):06d}",
                name=f"Recorder project {int(turn['accepted_seq'])}",
                description="Automatically created by the project router seam",
                idempotency_key=turn["turn_id"],
            )
            projects = [auto]
            try:
                decision = self.router.decide(turn, projects)
            except Exception:
                return self.store.commit_routing_error(turn["turn_id"], owner=owner)
        if decision is None:
            return self.store.commit_routing_error(turn["turn_id"], owner=owner)
        return self.store.commit_route(turn["turn_id"], decision, owner=owner)

    def route_turn(self, turn_id: str, decision: RouterDecision, *, owner: str | None = None) -> dict[str, Any]:
        return self.store.commit_route(turn_id, decision, owner=owner)

    def process_next_hermes(self, session_id: str, owner: str = "hermes-1") -> dict[str, Any] | None:
        if self.hermes is None:
            raise ValidationError("Hermes adapter is not configured")
        ingress = self.store.claim_session_ingress(session_id, owner)
        if ingress is None:
            return None
        payload = ingress["payload"]
        try:
            result = self.hermes.submit(
                session_key=ingress["gateway_session_key"],
                request=payload,
                submission_id=ingress["hermes_submission_id"],
                marker=ingress["marker"],
            )
        except Exception:
            result = None
        if result is None:
            try:
                result = self.hermes.history(session_key=ingress["gateway_session_key"], marker=ingress["marker"])
            except Exception:
                result = None
        if result is not None:
            combined_content = self._requery_combined_content(ingress, result)
            return self.store.commit_hermes_result(ingress["hermes_submission_id"], result, combined_content=combined_content)
        if ingress["attempt_count"] >= self.hermes_max_attempts:
            return self.store.commit_hermes_error(ingress["hermes_submission_id"], grace_seconds=self.hermes_grace_seconds)
        self.store.release_session_ingress(ingress["hermes_submission_id"], owner=owner)
        return self.store.get_turn(ingress["turn_id"])

    def _requery_combined_content(self, ingress: Mapping[str, Any], result: HermesResult) -> str | None:
        turn = self.store.get_turn(ingress["turn_id"])
        if not turn.get("final_event_version") or turn.get("final_content"):
            return None
        history_method = getattr(self.hermes, "history_messages", None)
        if history_method is None:
            return None
        try:
            messages = history_method(session_key=ingress["gateway_session_key"], marker=ingress["marker"])
        except Exception:
            return None
        values: list[str] = []
        seen: set[str] = set()
        if turn.get("final_outcome") == "error" and turn.get("final_error_kind") == "hermes":
            fixed = normalize_hermes_text(FINAL_ERROR_MESSAGES["hermes"])
            values.append(fixed)
            seen.add(hermes_content_hash(fixed))
        for item in list(messages or []) + [result]:
            text = normalize_hermes_text(item.content)
            digest = hermes_content_hash(text)
            if digest not in seen:
                seen.add(digest)
                values.append(text)
        return "\n".join(values) if values else None

    def run_asr(self, turn_id: str) -> dict[str, Any]:
        turn = self.store.get_turn(turn_id)
        audio_parts = [part for part in turn["parts"] if part["kind"] == "audio"]
        if not audio_parts:
            return turn
        audio = b"".join(self.store.read_part(turn_id, part["part_id"]) for part in audio_parts)
        stage_order = ["realtime", "batch", "local"]
        generation = int(turn["asr_generation"])
        for index, stage in enumerate(stage_order):
            current = self.store.get_turn(turn_id)
            if current["authoritative_asr_outcome"]:
                return current
            next_generation = self.store.set_asr_stage(turn_id, expected_generation=generation, stage=stage)
            if next_generation is None:
                return self.store.get_turn(turn_id)
            provider = self.asr_providers.get(stage)
            result = AsrResult.error("provider unavailable") if provider is None else provider.transcribe(audio, turn_id=turn_id, generation=next_generation)
            if result.outcome == "VALID_TRANSCRIPT":
                self.store.commit_asr_result(turn_id, expected_generation=next_generation, stage=stage, result=result)
                return self.store.get_turn(turn_id)
            if index < len(stage_order) - 1:
                self.store.commit_asr_result(
                    turn_id,
                    expected_generation=next_generation,
                    stage=stage,
                    result=result,
                    authoritative=False,
                )
                generation = next_generation
                continue
            self.store.commit_asr_result(turn_id, expected_generation=next_generation, stage=stage, result=result)
            self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"])
            return self.store.get_turn(turn_id)
        return self.store.get_turn(turn_id)

    def generate_tts(self, artifact_id: str) -> dict[str, Any]:
        artifact = self.store.get_artifact(artifact_id)
        if artifact["status"] in {"PLAYED", "EXPIRED"}:
            return artifact
        try:
            result = self.tts.synthesize(artifact["source_text"], artifact_id=artifact_id)
        except Exception as exc:  # provider failures stay separate from text FINAL
            return self.store.set_tts_result(artifact_id, None, error=str(exc))
        return self.store.set_tts_result(artifact_id, result)

    def generate_pending_tts(self, *, limit: int = 50) -> list[dict[str, Any]]:
        results = []
        for artifact in self.store.pending_tts(limit=limit):
            results.append(self.generate_tts(artifact["artifact_id"]))
        return results

    def schedule_create(self, command: Mapping[str, Any]) -> dict[str, Any]:
        return self.schedule_adapter.schedule_create(command)

    def run_scheduler(
        self,
        *,
        owner: str = "scheduler-1",
        lease_seconds: int = 30,
        limit: int = 50,
        now: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.store.fire_due_schedules(owner=owner, lease_seconds=lease_seconds, limit=limit, now=now)

    def recover_scheduler(self, *, now: str | None = None) -> dict[str, Any]:
        return self.store.recover(now=now)

    def accept_text_turn(self, manifest: Mapping[str, Any], text: str) -> dict[str, Any]:
        manifest = dict(manifest)
        if manifest.get("parts"):
            raise ValidationError("accept_text_turn expects a manifest without parts")
        if not isinstance(text, str):
            raise ValidationError("text must be a JSON string")
        payload = text.encode("utf-8")
        manifest["parts"] = [
            {
                "part_id": "text-1",
                "kind": "text",
                "mime": "text/plain",
                "declared_bytes": len(payload),
                "declared_sha256": hashlib.sha256(payload).hexdigest(),
                "relationship": None,
                "caption_hash": None,
            }
        ]
        self.store.create_turn(manifest)
        self.store.put_chunk(manifest["turn_id"], "text-1", 0, payload)
        self.store.finish_part(
            manifest["turn_id"],
            "text-1",
            total_chunks=1,
            total_bytes=len(payload),
            whole_stream_sha256=hashlib.sha256(payload).hexdigest(),
        )
        return self.store.accept_turn(manifest["turn_id"])

    # ---- Small HTTP surface ----------------------------------------------

    def handle_http(self, method: str, target: str, headers: Mapping[str, str], body: bytes) -> tuple[int, dict[str, str], Any]:
        try:
            return self._handle_http(method, target, headers, body)
        except RecorderError as exc:
            return exc.status, {"Content-Type": "application/json"}, {"error": {"code": exc.code, "message": exc.message}}
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            return 400, {"Content-Type": "application/json"}, {"error": {"code": "INVALID_JSON", "message": str(exc)}}
        except Exception:
            return 500, {"Content-Type": "application/json"}, {"error": {"code": "INTERNAL_ERROR", "message": "request failed"}}

    @staticmethod
    def _json_body(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValidationError("JSON body must be an object")
        return value

    @staticmethod
    def _json_string(payload: Mapping[str, Any], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise ValidationError(f"{key} is required and must be a non-empty string")
        return value

    @staticmethod
    def _json_integer(payload: Mapping[str, Any], key: str, *, allow_none: bool = False) -> int | None:
        if key not in payload:
            raise ValidationError(f"{key} is required")
        value = payload[key]
        if allow_none and value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(f"{key} must be a native JSON integer")
        return value

    @staticmethod
    def _query_integer(
        query: Mapping[str, str],
        key: str,
        *,
        default: int | None = None,
        minimum: int = 0,
        maximum: int | None = None,
    ) -> int | None:
        value = query.get(key)
        if value is None:
            return default
        if not value.isdigit():
            raise ValidationError(f"{key} must be a non-negative integer")
        parsed = int(value)
        if parsed < minimum:
            raise ValidationError(f"{key} must be at least {minimum}")
        if maximum is not None and parsed > maximum:
            raise ValidationError(f"{key} exceeds configured maximum of {maximum}")
        return parsed

    def _handle_http(self, method: str, target: str, headers: Mapping[str, str], body: bytes) -> tuple[int, dict[str, str], Any]:
        parsed = urlsplit(target)
        path = parsed.path.rstrip("/") or "/"
        query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
        if method == "GET" and path in {"/healthz", "/v1/health"}:
            return 200, {}, {"status": "ok", "product_identity": "recorder-next-server-v1", "api_version": "v1"}
        if method == "GET" and path == "/v1/openapi.json":
            from .openapi import OPENAPI

            return 200, {}, OPENAPI
        segments = [unquote(item) for item in path.split("/") if item]
        if segments[:3] == ["v1", "internal", "schedule_create"] and method == "POST":
            if headers.get("X-Recorder-Internal-Trusted") != "1":
                raise UnauthorizedError("schedule_create requires the trusted Recorder adapter")
            return 201, {}, self.schedule_create(self._json_body(body))
        if segments[:3] == ["v1", "internal", "scheduler"] and len(segments) == 4 and segments[3] == "fire" and method == "POST":
            payload = self._json_body(body)
            items = self.run_scheduler(
                owner=str(payload.get("owner", "scheduler-1")),
                lease_seconds=int(payload.get("lease_seconds", 30)),
                limit=int(payload.get("limit", 50)),
                now=payload.get("now"),
            )
            return 200, {}, {"items": items}
        if segments[:3] == ["v1", "internal", "scheduler"] and len(segments) == 4 and segments[3] == "recover" and method == "POST":
            payload = self._json_body(body)
            return 200, {}, self.recover_scheduler(now=payload.get("now"))
        if segments[:2] == ["v1", "schedules"] and len(segments) == 3 and method == "GET":
            return 200, {}, self.store.get_schedule(segments[2])
        if segments[:2] == ["v1", "devices"] and len(segments) == 2 and method == "POST":
            payload = self._json_body(body)
            return 201, {}, self.store.register_device(payload["user_id"], payload["device_id"], payload["kind"])
        if segments[:2] == ["v1", "devices"] and len(segments) == 4 and segments[3] == "revoke" and method == "POST":
            payload = self._json_body(body)
            self.store.revoke_device(payload["user_id"], segments[2])
            return 200, {}, self.store.get_device(payload["user_id"], segments[2])
        if segments[:2] == ["v1", "turns"] and len(segments) == 2 and method == "POST":
            payload = self._json_body(body)
            if "text" in payload and not payload.get("parts"):
                if not isinstance(payload["text"], str):
                    raise ValidationError("text must be a JSON string")
                manifest = {key: value for key, value in payload.items() if key != "text"}
                return 202, {}, self.accept_text_turn(manifest, payload["text"])
            return 201, {}, self.store.create_turn(payload)
        if segments[:2] == ["v1", "turns"] and len(segments) == 4 and segments[3] == "accept" and method == "POST":
            return 200, {}, self.store.accept_turn(segments[2])
        if segments[:2] == ["v1", "turns"] and len(segments) == 3:
            turn_id = segments[2]
            if method == "GET":
                return 200, {}, self.store.get_turn(turn_id)
        if len(segments) >= 5 and segments[:2] == ["v1", "turns"] and segments[3] == "parts":
            turn_id, part_id = segments[2], segments[4]
            if len(segments) == 6 and segments[5] == "missing" and method == "GET":
                total = self._query_integer(query, "total_chunks")
                offset = self._query_integer(query, "offset", default=0)
                limit = self._query_integer(query, "limit", default=DEFAULT_MISSING_PAGE_SIZE, minimum=1, maximum=MAX_MISSING_PAGE_SIZE)
                page = self.store.missing_sequence_page(
                    turn_id,
                    part_id,
                    total,
                    offset=offset or 0,
                    limit=limit or DEFAULT_MISSING_PAGE_SIZE,
                    encoding=query.get("encoding", "list"),
                )
                return 200, {}, {"turn_id": turn_id, "part_id": part_id, **page}
            if len(segments) == 7 and segments[5] == "chunks" and method in {"PUT", "POST"}:
                sequence = int(segments[6])
                result = self.store.put_chunk(turn_id, part_id, sequence, body, expected_sha256=headers.get("X-Chunk-SHA256"))
                return 200, {}, result
            if len(segments) == 6 and segments[5] == "finish" and method == "POST":
                payload = self._json_body(body)
                return 200, {}, self.store.finish_part(
                    turn_id,
                    part_id,
                    total_chunks=self._json_integer(payload, "total_chunks"),
                    total_bytes=self._json_integer(payload, "total_bytes"),
                    whole_stream_sha256=payload["whole_stream_sha256"],
                    duration_ms=self._json_integer(payload, "duration_ms", allow_none=True) if "duration_ms" in payload else None,
                )
        if len(segments) in {5, 6} and segments[:2] == ["v1", "turns"] and segments[3] == "events" and (len(segments) == 5 or segments[5] == "ack") and method == "POST":
            payload = self._json_body(body)
            return 200, {}, self.store.ack_event(segments[2], segments[4], device_id=str(payload["device_id"]), event_version=int(payload["event_version"]), payload_sha256=str(payload["payload_sha256"]))
        if segments[:2] == ["v1", "outbox"] and method == "GET":
            return 200, {}, {"items": self.store.pending_outbox(query["device_id"], limit=int(query.get("limit", "50")))}
        if len(segments) == 4 and segments[:2] == ["v1", "tts"] and segments[3] == "bridge-read" and method == "GET":
            bridge_device_id = query.get("device_id")
            if not bridge_device_id:
                raise ValidationError("device_id is required for TTS bridge reads")
            metadata, audio = self.store.read_tts_for_bridge(segments[2], bridge_device_id=bridge_device_id)
            metadata["audio_base64"] = base64.b64encode(audio).decode("ascii")
            return 200, {}, metadata
        if segments[:2] == ["v1", "tts"] and len(segments) == 3 and method == "GET":
            device_id = query.get("device_id") or headers.get("X-Recorder-Device-ID")
            if not device_id:
                raise ValidationError("device_id is required for TTS reads")
            metadata, audio = self.store.read_tts(segments[2], device_id=device_id)
            metadata["audio_base64"] = base64.b64encode(audio).decode("ascii")
            return 200, {}, metadata
        if len(segments) == 4 and segments[:2] == ["v1", "tts"] and segments[3] == "playback-ack" and method == "POST":
            payload = self._json_body(body)
            return 200, {}, self.store.ack_playback(
                segments[2],
                device_id=self._json_string(payload, "device_id"),
                payload_sha256=self._json_string(payload, "payload_sha256"),
                turn_id=self._json_string(payload, "turn_id"),
                artifact_version=self._json_integer(payload, "artifact_version"),
            )
        if len(segments) == 4 and segments[:2] == ["v1", "tts"] and segments[3] == "relay-received" and method == "POST":
            payload = self._json_body(body)
            return 200, {}, self.store.relay_tts_received(segments[2], device_id=str(payload["device_id"]), payload_sha256=str(payload["payload_sha256"]))
        if segments[:2] == ["v1", "projects"] and len(segments) == 2:
            if method == "GET":
                return 200, {}, {"items": self.store.list_projects(query["user_id"], include_archived=query.get("include_archived") == "true")}
            if method == "POST":
                payload = self._json_body(body)
                return 201, {}, self.store.create_project(payload["user_id"], project_number=payload["project_number"], name=payload["name"], aliases=payload.get("aliases"), description=payload.get("description", ""), idempotency_key=payload.get("idempotency_key"))
        if segments[:3] == ["v1", "projects", "search"] and method == "GET":
            return 200, {}, {"items": self.store.search_projects(query["user_id"], query.get("q", ""), include_archived=query.get("include_archived") == "true")}
        if segments[:2] == ["v1", "projects"] and len(segments) >= 3:
            project_id = segments[2]
            if len(segments) == 3 and method == "GET":
                return 200, {}, self.store.get_project(query["user_id"], project_id, include_archived=True)
            if len(segments) == 3 and method == "PATCH":
                payload = self._json_body(body)
                return 200, {}, self.store.update_project(query["user_id"], project_id, expected_version=int(payload.pop("expected_version")), patch=payload)
            if len(segments) == 4 and segments[3] == "archive" and method == "POST":
                payload = self._json_body(body)
                return 200, {}, self.store.archive_project(query["user_id"], project_id, expected_version=int(payload["expected_version"]))
        if segments[:2] == ["v1", "turns"] and len(segments) == 4 and segments[3] == "archive" and method == "POST":
            payload = self._json_body(body)
            return 200, {}, self.store.archive_turn(query["user_id"], segments[2], source=str(payload.get("source", "api")))
        if segments[:3] == ["v1", "internal", "router"] and method == "POST":
            payload = self._json_body(body)
            return 200, {}, self.route_next(payload["user_id"], payload.get("owner", "router-1"))
        if segments[:3] == ["v1", "internal", "hermes"] and method == "POST":
            payload = self._json_body(body)
            return 200, {}, self.process_next_hermes(payload["session_id"], payload.get("owner", "hermes-1"))
        if segments[:3] == ["v1", "internal", "tts"] and method == "POST":
            payload = self._json_body(body)
            return 200, {}, self.generate_pending_tts(limit=int(payload.get("limit", 50)))
        raise NotFoundError("API route not found")


def create_service(db_path: str, storage_root: str, *, clock: Any | None = None, **kwargs: Any) -> RecorderService:
    return RecorderService(RecorderStore(db_path, storage_root=storage_root, clock=clock), **kwargs)


def create_configured_service(config: "RecorderConfig") -> RecorderService:
    from .config import RecorderConfig

    if not isinstance(config, RecorderConfig):
        raise TypeError("config must be RecorderConfig")
    hermes = None
    if config.hermes_base_url:
        from .adapters import CredentialError, HttpHermesGateway

        if not config.hermes_api_key_file:
            raise CredentialError("Hermes API credential path is required")
        hermes = HttpHermesGateway(config.hermes_base_url, api_key_file=config.hermes_api_key_file)
    store = RecorderStore(
        config.database,
        storage_root=config.storage_root,
        max_chunk_bytes=config.max_chunk_bytes,
        max_turn_bytes=config.max_turn_bytes,
        max_audio_bytes=config.max_audio_bytes,
        max_audio_minutes=config.max_audio_minutes,
        max_text_bytes=config.max_text_bytes,
        max_attachment_bytes=config.max_attachment_bytes,
        max_parts=config.max_parts,
        min_free_bytes=config.min_free_bytes,
    )
    return RecorderService(store, hermes=hermes, hermes_max_attempts=config.hermes_max_attempts, hermes_grace_seconds=config.hermes_grace_seconds)
