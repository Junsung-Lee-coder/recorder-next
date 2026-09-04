from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import threading
from dataclasses import asdict
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, unquote, urlsplit

from .adapters import (
    ASRProvider,
    ChainFailure,
    DeterministicRouter,
    DisabledTTSProvider,
    EdgeTTSProvider,
    HermesGateway,
    HermesAudioASRProvider,
    HermesAudioTTSProvider,
    HttpASRProvider,
    HttpTTSProvider,
    NemotronASRProvider,
    ProviderChain,
    ProviderFailure,
    ProviderTarget,
    RouterAdapter,
    StaticASRProvider,
    StaticTTSProvider,
    TrustedScheduleCreateAdapter,
    TTSProvider,
    WhisperASRProvider,
)
from .canonical import hermes_content_hash, normalize_hermes_text
from .config import RecorderConfig
from .errors import NotFoundError, RecorderError, UnauthorizedError, ValidationError
from .features import DurableWorker
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
        asr_chain: ProviderChain | None = None,
        tts_chain: ProviderChain | None = None,
        asr_chains: Mapping[str, ProviderChain] | None = None,
        tts_chains: Mapping[str, ProviderChain] | None = None,
        eavesdrop_agent: Any | None = None,
        asr_fallback_order: Sequence[str] = ("realtime", "batch", "local"),
        hermes_max_attempts: int = 2,
        hermes_grace_seconds: int = 30,
    ):
        self.store = store
        self.router = router or DeterministicRouter()
        self.hermes = hermes
        self.asr_providers = dict(asr_providers or {})
        self.asr_chain = asr_chain
        self.tts_chain = tts_chain
        self.asr_chains = dict(asr_chains or {})
        self.tts_chains = dict(tts_chains or {})
        self.eavesdrop_agent = eavesdrop_agent
        if any(item not in {"realtime", "batch", "local"} for item in asr_fallback_order):
            raise ValueError("invalid ASR fallback order")
        self.asr_fallback_order = tuple(asr_fallback_order)
        if eavesdrop_agent is not None:
            self.store._features.eavesdrop_agent = eavesdrop_agent
        self.tts = tts or (tts_chain.targets[0].provider if tts_chain is not None else StaticTTSProvider())
        self.schedule_adapter = TrustedScheduleCreateAdapter(store)
        self.hermes_max_attempts = max(1, hermes_max_attempts)
        self.hermes_grace_seconds = max(0, hermes_grace_seconds)
        self._lock = threading.RLock()

    @staticmethod
    def _turn_scopes(turn: Mapping[str, Any], *, eavesdrop: bool = False) -> tuple[str, ...]:
        scopes: list[str] = []
        if eavesdrop:
            scopes.append("eavesdrop")
        manifest = turn.get("manifest") if isinstance(turn.get("manifest"), Mapping) else {}
        project_id = turn.get("project_id") or manifest.get("project_id") or manifest.get("current_project_number")
        if isinstance(project_id, str) and project_id:
            scopes.extend((f"project:{project_id}", project_id))
        input_type = turn.get("input_type") or manifest.get("input_type")
        if not isinstance(input_type, str) or not input_type:
            part_kinds = {item.get("kind") for item in turn.get("parts", []) if isinstance(item, Mapping) and isinstance(item.get("kind"), str)}
            if len(part_kinds) == 1:
                input_type = next(iter(part_kinds))
            elif part_kinds:
                input_type = "mixed"
        if isinstance(input_type, str) and input_type:
            scopes.extend((f"input_type:{input_type}", f"input-type:{input_type}", input_type))
        return tuple(scopes)

    def _chain_for_turn(self, kind: str, turn: Mapping[str, Any], *, eavesdrop: bool = False) -> ProviderChain | None:
        chains = self.asr_chains if kind == "asr" else self.tts_chains
        for scope in self._turn_scopes(turn, eavesdrop=eavesdrop):
            selected = chains.get(scope)
            if selected is not None:
                return selected
        return self.asr_chain if kind == "asr" else self.tts_chain

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
        routed = self.store.commit_route(turn["turn_id"], decision, owner=owner)
        self._enqueue_hermes_job(routed)
        return routed

    def route_turn(self, turn_id: str, decision: RouterDecision, *, owner: str | None = None) -> dict[str, Any]:
        routed = self.store.commit_route(turn_id, decision, owner=owner)
        self._enqueue_hermes_job(routed)
        return routed

    def process_eavesdrop_segment(self, session_id: str, segment_sequence: int, *, owner: str = "eavesdrop-1", now: str | None = None, expected_segment_sha256: str | None = None) -> dict[str, Any] | None:
        session = self.store.get_eavesdrop_session(session_id, now=now)
        decision = next((item for item in session.get("routing_decisions", []) if item.get("segment_sequence") == segment_sequence), None)
        if decision is None:
            raise ValidationError("eavesdrop routing decision is missing")
        if decision.get("decision") != "FORWARD_DEFAULT" or decision.get("result_state") != "QUEUED":
            return {"session_id": session_id, "segment_sequence": segment_sequence, "state": decision.get("result_state"), "outcome": decision.get("decision"), "reason": decision.get("reason")}
        if session.get("state") == "EXPIRED":
            failed = self.store.mark_eavesdrop_decision(session_id, segment_sequence, result_state="FAILED", reason="session_expired")
            return {"session_id": session_id, "segment_sequence": segment_sequence, "state": failed.get("result_state", "FAILED"), "outcome": failed.get("decision"), "reason": failed.get("reason")}
        if self.hermes is None:
            raise ProviderFailure("provider_unavailable", retryable=False)
        segments = sorted(
            (item for item in session.get("segments", []) if isinstance(item, Mapping) and int(item.get("sequence", -1)) <= segment_sequence),
            key=lambda item: int(item.get("sequence", -1)),
        )
        segment = next((item for item in session.get("segments", []) if item.get("sequence") == segment_sequence), None)
        if segment is None:
            raise ValidationError("eavesdrop segment is missing")
        if expected_segment_sha256 is not None and expected_segment_sha256 != segment.get("sha256"):
            raise ValidationError("eavesdrop segment digest does not match the queued job")
        if not segment.get("transcript"):
            self.store.mark_eavesdrop_decision(session_id, segment_sequence, result_state="NO_SPEECH", reason="segment_has_no_transcript")
            return {"session_id": session_id, "segment_sequence": segment_sequence, "state": "NO_SPEECH"}
        conversation = "\n".join(str(item["transcript"]).strip() for item in segments if isinstance(item.get("transcript"), str) and item["transcript"].strip())
        if not conversation:
            self.store.mark_eavesdrop_decision(session_id, segment_sequence, result_state="NO_SPEECH", reason="conversation_has_no_transcript")
            return {"session_id": session_id, "segment_sequence": segment_sequence, "state": "NO_SPEECH"}
        request = {"input": conversation}
        result: HermesResult | None = None
        try:
            result = self.hermes.submit(
                session_key=str(decision["gateway_session_key"]),
                request=request,
                submission_id=str(decision["hermes_submission_id"]),
                marker=f"eavesdrop:default:{session_id}:{segment_sequence}",
            )
        except Exception:
            result = None
        if result is None:
            try:
                result = self.hermes.history(session_key=str(decision["gateway_session_key"]), marker=f"eavesdrop:default:{session_id}:{segment_sequence}")
            except Exception:
                result = None
        if result is None:
            raise ProviderFailure("transport", retryable=True)
        if not result.terminal or not isinstance(result.content, str) or not result.content.strip():
            raise ProviderFailure("malformed_response", retryable=False)
        reply = None
        if session.get("response_enabled") and result.content:
            reply = self.store.record_eavesdrop_reply(session_id, segment_sequence=segment_sequence, text=result.content)
        effect_receipt: dict[str, Any] = {
            "submission_id": decision["hermes_submission_id"],
            "session_id": session_id,
            "segment_sequence": segment_sequence,
            "segment_sha256": segment.get("sha256"),
            "gateway_profile": "default",
            "input_sha256": hashlib.sha256(conversation.encode("utf-8")).hexdigest(),
            "content_hash": hermes_content_hash(result.content),
            "assistant_message_id": result.assistant_message_id,
            "provider": result.source,
        }
        if reply is not None:
            effect_receipt["reply_id"] = reply["reply_id"]
        self.store.mark_eavesdrop_decision(
            session_id,
            segment_sequence,
            result_state="DELIVERED",
            reason="hermes_response_available",
            effect_receipt=effect_receipt,
        )
        return {"session_id": session_id, "segment_sequence": segment_sequence, "state": "DELIVERED", "reply_id": reply.get("reply_id") if reply else None, "content_hash": hermes_content_hash(result.content)}

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
            committed = self.store.commit_hermes_result(ingress["hermes_submission_id"], result, combined_content=combined_content)
            self._enqueue_tts_jobs(ingress["turn_id"])
            return committed
        if ingress["attempt_count"] >= self.hermes_max_attempts:
            failed = self.store.commit_hermes_error(ingress["hermes_submission_id"], grace_seconds=self.hermes_grace_seconds)
            self._enqueue_tts_jobs(ingress["turn_id"])
            return failed
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

    def run_asr(self, turn_id: str, *, frozen: Mapping[str, Any] | None = None) -> dict[str, Any]:
        turn = self.store.get_turn(turn_id)
        if turn.get("authoritative_asr_outcome"):
            return turn
        audio_parts = [part for part in turn["parts"] if part["kind"] == "audio"]
        if not audio_parts:
            return turn
        audio = b"".join(self.store.read_part(turn_id, part["part_id"]) for part in audio_parts)
        chain = self._chain_for_turn("asr", turn)
        if chain is not None:
            generation = int(turn["asr_generation"])
            next_generation = self.store.set_asr_stage(turn_id, expected_generation=generation, stage="provider-chain")
            if next_generation is None:
                return self.store.get_turn(turn_id)
            try:
                result = chain.execute_asr(audio, turn_id=turn_id, frozen=frozen)
            except ChainFailure as exc:
                result = AsrResult(
                    "PROVIDER_ERROR",
                    detail=exc.kind,
                    metadata={
                        "chain_generation": chain.generation,
                        "chain_fingerprint": chain.fingerprint,
                        "statuses": [dict(item) for item in exc.statuses],
                    },
                )
                self.store.commit_asr_result(turn_id, expected_generation=next_generation, stage="provider-chain", result=result)
                self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"])
                return self.store.get_turn(turn_id)
            self.store.commit_asr_result(turn_id, expected_generation=next_generation, stage="provider-chain", result=result)
            committed = self.store.get_turn(turn_id)
            if result.outcome == "VALID_TRANSCRIPT":
                self._enqueue_turn_stage(committed)
            return committed
        stage_order = list(self.asr_fallback_order)
        if not stage_order:
            self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"])
            return self.store.get_turn(turn_id)
        generation = int(turn["asr_generation"])
        for index, stage in enumerate(stage_order):
            current = self.store.get_turn(turn_id)
            if current["authoritative_asr_outcome"]:
                return current
            next_generation = self.store.set_asr_stage(turn_id, expected_generation=generation, stage=stage)
            if next_generation is None:
                return self.store.get_turn(turn_id)
            provider = self.asr_providers.get(stage)
            provider_failure: ProviderFailure | None = None
            if provider is None:
                result = AsrResult.error("provider unavailable")
            else:
                try:
                    result = provider.transcribe(audio, turn_id=turn_id, generation=next_generation)
                except ProviderFailure as exc:
                    provider_failure = exc
                    result = AsrResult.error(exc.kind)
            # Silence is a successful, authoritative provider result.  It is
            # not permission to send the same media to a fallback provider.
            if result.outcome == "NO_SPEECH":
                self.store.commit_asr_result(turn_id, expected_generation=next_generation, stage=stage, result=result)
                return self.store.get_turn(turn_id)
            if result.outcome == "VALID_TRANSCRIPT":
                self.store.commit_asr_result(turn_id, expected_generation=next_generation, stage=stage, result=result)
                committed = self.store.get_turn(turn_id)
                self._enqueue_turn_stage(committed)
                return committed
            # Permanent provider failures (auth, unsupported media, malformed
            # success, policy, and other non-retryable errors) fail closed and
            # must never fall through to a later target.
            if provider_failure is not None and not provider_failure.retryable:
                self.store.commit_asr_result(
                    turn_id,
                    expected_generation=next_generation,
                    stage=stage,
                    result=result,
                )
                self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"])
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

    def generate_tts(self, artifact_id: str, *, frozen: Mapping[str, Any] | None = None) -> dict[str, Any]:
        artifact = self.store.get_artifact(artifact_id)
        if artifact["status"] in {"READY", "DELIVERY_PENDING", "PLAYED", "EXPIRED"}:
            return artifact
        try:
            turn = self.store.get_turn(artifact["turn_id"])
            chain = self._chain_for_turn("tts", turn)
            if chain is not None:
                result = chain.execute_tts(artifact["source_text"], artifact_id=artifact_id, frozen=frozen)
            else:
                result = self.tts.synthesize(artifact["source_text"], artifact_id=artifact_id)
        except ChainFailure as exc:
            return self.store.set_tts_result(artifact_id, None, error=exc.kind)
        except ProviderFailure as exc:  # provider failures stay separate from text FINAL
            return self.store.set_tts_result(artifact_id, None, error=exc.kind)
        except Exception:  # provider failures stay separate from text FINAL
            return self.store.set_tts_result(artifact_id, None, error="provider_error")
        return self.store.set_tts_result(artifact_id, result)

    def generate_pending_tts(self, *, limit: int = 50) -> list[dict[str, Any]]:
        results = []
        for artifact in self.store.pending_tts(limit=limit):
            results.append(self.generate_tts(artifact["artifact_id"]))
        return results

    def run_durable_worker_once(
        self,
        *,
        owner: str,
        handlers: Mapping[str, Any],
        now: str | None = None,
        lease_seconds: int = 30,
    ) -> dict[str, Any] | None:
        """Run one restart-safe generic job; handlers must return receipts."""
        worker = DurableWorker(self.store, owner=owner, handlers=handlers)
        return worker.run_once(now=now, lease_seconds=lease_seconds)

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

    def _enqueue_stage_job(
        self,
        stage: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
        provider_chain: ProviderChain | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        return self.store.enqueue_worker_job(
            kind=stage,
            stage=stage,
            payload=dict(payload),
            idempotency_key=idempotency_key,
            max_attempts=self.hermes_max_attempts if stage == "hermes" else 3,
            now=now,
            provider_chain=provider_chain,
            deadline_seconds=(
                max(1, int(math.ceil(provider_chain.overall_deadline_seconds)))
                if provider_chain is not None
                else (180 if stage in {"asr", "tts"} else 300)
            ),
        )

    def _enqueue_turn_stage(self, turn: Mapping[str, Any], *, now: str | None = None) -> dict[str, Any] | None:
        if turn.get("state") not in {"ACCEPTED", "ASR_PENDING"}:
            return None
        audio = any(part.get("kind") == "audio" for part in turn.get("parts", []))
        asr_outcome = turn.get("authoritative_asr_outcome")
        stage = "asr" if audio and asr_outcome not in {"VALID_TRANSCRIPT", "NO_SPEECH"} else "route"
        chain = self._chain_for_turn("asr", turn) if stage == "asr" else None
        return self._enqueue_stage_job(
            stage,
            {"turn_id": turn["turn_id"], "user_id": turn["user_id"]},
            idempotency_key=f"turn:{turn['turn_id']}:{stage}",
            provider_chain=chain,
            now=now,
        )

    def _enqueue_hermes_job(self, turn: Mapping[str, Any], *, now: str | None = None) -> dict[str, Any] | None:
        if not turn.get("project_id") or not turn.get("session_key"):
            return None
        return self._enqueue_stage_job(
            "hermes",
            {"turn_id": turn["turn_id"], "session_id": turn["project_id"]},
            idempotency_key=f"turn:{turn['turn_id']}:hermes",
            now=now,
        )

    def _enqueue_tts_jobs(self, turn_id: str, *, now: str | None = None) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        for artifact in self.store.pending_tts(limit=500):
            if artifact.get("turn_id") != turn_id:
                continue
            turn = self.store.get_turn(turn_id)
            jobs.append(
                self._enqueue_stage_job(
                    "tts",
                    {"turn_id": turn_id, "artifact_id": artifact["artifact_id"]},
                    idempotency_key=f"artifact:{artifact['artifact_id']}:tts",
                    provider_chain=self._chain_for_turn("tts", turn),
                    now=now,
                )
            )
        return jobs

    def accept_turn(self, turn_id: str, *, now: str | None = None) -> dict[str, Any]:
        accepted = self.store.accept_turn(turn_id, now=now)
        if accepted.get("state") == "ACCEPTED":
            self._enqueue_turn_stage(accepted, now=now)
        return accepted

    def _default_worker_handlers(self) -> dict[str, Any]:
        def receipt(stage: str, identifier: str, *, status: str = "accepted", **extra: Any) -> dict[str, Any]:
            value: dict[str, Any] = {"effect_id": f"recorder:{stage}:{identifier}", "status": status}
            for key, item in extra.items():
                if isinstance(item, (str, int, float, bool)) or item is None:
                    value[key] = item
            return value

        def asr(job: Mapping[str, Any]) -> Mapping[str, Any]:
            result = self.run_asr(str(job["payload"]["turn_id"]), frozen=job.get("provider_chain"))
            return receipt("asr", str(job["payload"]["turn_id"]), outcome=result.get("authoritative_asr_outcome") or "pending")

        def route(job: Mapping[str, Any]) -> Mapping[str, Any]:
            result = self.route_next(str(job["payload"]["user_id"]), owner=f"worker:{job['job_id']}")
            if result is None:
                raise ProviderFailure("provider_unavailable", retryable=True)
            return receipt("route", str(job["payload"]["turn_id"]), state=result.get("state", "accepted"))

        def hermes(job: Mapping[str, Any]) -> Mapping[str, Any]:
            try:
                result = self.process_next_hermes(str(job["payload"]["session_id"]), owner=f"worker:{job['job_id']}")
            except ValidationError:
                raise ProviderFailure("provider_unavailable", retryable=False) from None
            if result is None:
                raise ProviderFailure("provider_unavailable", retryable=True)
            if result.get("state") in {"ROUTED", "HERMES_PENDING"} and not result.get("final_event_version"):
                raise ProviderFailure("transport", retryable=True)
            return receipt("hermes", str(job["payload"]["turn_id"]), state=result.get("state", "accepted"))

        def eavesdrop(job: Mapping[str, Any]) -> Mapping[str, Any]:
            result = self.process_eavesdrop_segment(
                str(job["payload"]["session_id"]),
                int(job["payload"]["segment_sequence"]),
                owner=f"worker:{job['job_id']}",
                now=job.get("_worker_now"),
                expected_segment_sha256=job["payload"].get("segment_sha256"),
            )
            if result is None:
                raise ProviderFailure("provider_unavailable", retryable=True)
            return receipt("eavesdrop", f"{job['payload']['session_id']}:{job['payload']['segment_sequence']}", state=result.get("state", "accepted"))

        def tts(job: Mapping[str, Any]) -> Mapping[str, Any]:
            result = self.generate_tts(str(job["payload"]["artifact_id"]), frozen=job.get("provider_chain"))
            if result.get("status") == "FAILED_GENERATION":
                error_kind = "provider_unavailable"
                raw_metadata = result.get("provider_metadata_json")
                if isinstance(raw_metadata, str):
                    try:
                        parsed_metadata = json.loads(raw_metadata)
                        if isinstance(parsed_metadata, Mapping) and isinstance(parsed_metadata.get("error_kind"), str):
                            error_kind = parsed_metadata["error_kind"]
                    except json.JSONDecodeError:
                        pass
                retryable = error_kind in {"transport", "dns", "connect", "timeout", "rate_limited", "server", "provider_unavailable", "capacity"}
                raise ProviderFailure(error_kind, retryable=retryable)
            return receipt("tts", str(job["payload"]["artifact_id"]), state=result.get("status", "accepted"))

        def scheduler(job: Mapping[str, Any]) -> Mapping[str, Any]:
            result = self.run_scheduler(owner=f"worker:{job['job_id']}", now=job.get("payload", {}).get("now"))
            return receipt("scheduler", job["job_id"], count=len(result))

        return {"asr": asr, "route": route, "hermes": hermes, "eavesdrop": eavesdrop, "tts": tts, "scheduler": scheduler}

    def run_background_worker_once(self, *, owner: str = "recorder-worker-1", now: str | None = None, lease_seconds: int = 30) -> dict[str, Any] | None:
        return self.run_durable_worker_once(owner=owner, handlers=self._default_worker_handlers(), now=now, lease_seconds=lease_seconds)

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
        return self.accept_turn(manifest["turn_id"])

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
    def _header_value(headers: Mapping[str, str], name: str) -> str | None:
        wanted = name.lower()
        for key, value in headers.items():
            if str(key).lower() == wanted:
                return value
        return None

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
        if method == "HEAD":
            method = "GET"
        parsed = urlsplit(target)
        path = parsed.path.rstrip("/") or "/"
        query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
        if method == "GET" and path in {"/healthz", "/v1/health"}:
            return 200, {}, {"status": "ok", "product_identity": "recorder-next-server-product-items-1-through-8", "api_version": "v1", "worker": self.store.worker_health()}
        if method == "GET" and path == "/v1/openapi.json":
            from .openapi import OPENAPI

            return 200, {}, OPENAPI
        segments = [unquote(item) for item in path.split("/") if item]
        if segments[:2] == ["v1", "updates"] and len(segments) == 4 and segments[3] in {"manifest", "manifest.json"} and method == "GET":
            manifest = self.store.get_update_manifest(segments[2])
            if_none_match = self._header_value(headers, "If-None-Match")
            if if_none_match is not None and (if_none_match.strip() == "*" or manifest["etag"] in {item.strip() for item in if_none_match.split(",")}):
                return 304, {"ETag": manifest["etag"], "Cache-Control": "no-store"}, b""
            return 200, {"ETag": manifest["etag"], "Cache-Control": "no-store"}, manifest
        if segments[:2] == ["v1", "updates"] and len(segments) == 5 and method == "GET":
            result = self.store.read_update_artifact(
                segments[2],
                int(segments[3]),
                segments[4],
                range_header=self._header_value(headers, "Range"),
                if_range=self._header_value(headers, "If-Range"),
                if_none_match=self._header_value(headers, "If-None-Match"),
            )
            return result["status"], result["headers"], result["body"]
        if segments[:3] == ["v1", "internal", "worker"] and method == "POST":
            payload = self._json_body(body)
            action = segments[3] if len(segments) > 3 else "claim"
            if action == "claim":
                owner = self._json_string(payload, "owner") if "owner" in payload else "worker-1"
                lease_seconds = self._json_integer(payload, "lease_seconds") if "lease_seconds" in payload else 30
                assert lease_seconds is not None
                return 200, {}, self.store.claim_worker_job(owner, now=payload.get("now"), lease_seconds=lease_seconds) or {"job": None}
            if action == "recover":
                return 200, {}, self.store.recover_worker_jobs(now=payload.get("now"))
            if action == "complete":
                return 200, {}, self.store.complete_worker_job(self._json_string(payload, "job_id"), self._json_string(payload, "owner"), payload["receipt"], now=payload.get("now"))
            if action == "fail":
                error_kind = self._json_string(payload, "error_kind") if "error_kind" in payload else "internal"
                retryable = payload.get("retryable", False)
                if not isinstance(retryable, bool):
                    raise ValidationError("retryable must be boolean")
                return 200, {}, self.store.fail_worker_job(self._json_string(payload, "job_id"), self._json_string(payload, "owner"), error_kind=error_kind, retryable=retryable, now=payload.get("now"))
            if action == "run":
                owner = self._json_string(payload, "owner") if "owner" in payload else "worker-1"
                lease_seconds = self._json_integer(payload, "lease_seconds") if "lease_seconds" in payload else 30
                assert lease_seconds is not None
                return 200, {}, self.run_background_worker_once(owner=owner, now=payload.get("now"), lease_seconds=lease_seconds) or {"job": None}
        if segments[:4] == ["v1", "internal", "worker", "health"] and method == "GET":
            return 200, {}, self.store.worker_health(now=query.get("now"))
        if segments[:2] == ["v1", "history"] and len(segments) == 2 and method == "GET":
            if "user_id" not in query:
                raise ValidationError("user_id is required for history reads")
            since_seq = self._query_integer(query, "since_seq", minimum=0)
            return 200, {}, self.store.history_read_model(
                query["user_id"],
                project_id=query.get("project_id"),
                include_archived=query.get("include_archived") == "true",
                input_type=query.get("input_type"),
                cursor=query.get("cursor"),
                since_seq=since_seq,
                limit=self._query_integer(query, "limit", default=50, minimum=1, maximum=200) or 50,
            )
        if segments[:2] == ["v1", "eavesdrop"] and len(segments) == 2 and method == "POST":
            payload = self._json_body(body)
            optional_string = lambda key: self._json_string(payload, key) if key in payload and payload[key] is not None else None
            expires_seconds = self._json_integer(payload, "expires_seconds") if "expires_seconds" in payload else 300
            return 201, {}, self.store.start_eavesdrop(
                self._json_string(payload, "user_id"),
                self._json_string(payload, "phone_device_id"),
                session_id=optional_string("session_id"),
                idempotency_key=optional_string("idempotency_key"),
                watch_device_id=optional_string("watch_device_id"),
                project_id=optional_string("project_id"),
                response_enabled=payload.get("response_enabled", True),
                tts_enabled=payload.get("tts_enabled", False),
                hermes_enabled=payload.get("hermes_enabled", False),
                mode=optional_string("mode"),
                expires_seconds=expires_seconds,
                now=payload.get("now"),
            )
        if segments[:2] == ["v1", "eavesdrop"] and len(segments) >= 3:
            session_id = segments[2]
            if len(segments) == 3 and method == "GET":
                if not query.get("user_id") or not query.get("phone_device_id"):
                    raise UnauthorizedError("eavesdrop read requires user_id and phone_device_id")
                return 200, {}, self.store.get_eavesdrop_session(session_id, user_id=query.get("user_id"), phone_device_id=query.get("phone_device_id"), now=query.get("now"))
            if len(segments) == 4 and segments[3] in {"activate", "pause", "resume", "stop"} and method == "POST":
                payload = self._json_body(body)
                args = (session_id, self._json_string(payload, "user_id"), self._json_string(payload, "phone_device_id"))
                action = segments[3]
                result = {"activate": self.store.activate_eavesdrop, "pause": self.store.pause_eavesdrop, "resume": self.store.resume_eavesdrop, "stop": self.store.stop_eavesdrop}[action](*args, now=payload.get("now"))
                return 200, {}, result
            if len(segments) == 4 and segments[3] == "segments" and method == "POST":
                payload = self._json_body(body)
                try:
                    audio = base64.b64decode(str(payload["audio_base64"]), validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise ValidationError("audio_base64 is invalid") from exc
                sequence = self._json_integer(payload, "sequence")
                return 201, {}, self.store.append_eavesdrop_segment(
                    session_id,
                    self._json_string(payload, "user_id"),
                    self._json_string(payload, "phone_device_id"),
                    sequence=sequence,
                    client_segment_id=self._json_string(payload, "client_segment_id"),
                    audio=audio,
                    transcript=payload.get("transcript"),
                    reply_text=payload.get("reply_text"),
                    now=payload.get("now"),
                )
            if len(segments) == 5 and segments[3] == "segments" and segments[4] == "route" and method == "POST":
                payload = self._json_body(body)
                return 200, {}, self.store.route_eavesdrop_segment(session_id, self._json_string(payload, "user_id"), self._json_string(payload, "phone_device_id"), segment_sequence=self._json_integer(payload, "segment_sequence"), now=payload.get("now"))
            if len(segments) == 6 and segments[3] == "segments" and segments[5] == "route" and method == "POST":
                payload = self._json_body(body)
                return 200, {}, self.store.route_eavesdrop_segment(session_id, self._json_string(payload, "user_id"), self._json_string(payload, "phone_device_id"), segment_sequence=int(segments[4]), now=payload.get("now"))
            if len(segments) == 4 and segments[3] == "decisions" and method == "GET":
                if not query.get("user_id") or not query.get("phone_device_id"):
                    raise UnauthorizedError("eavesdrop read requires user_id and phone_device_id")
                return 200, {}, {"items": self.store.list_eavesdrop_decisions(session_id, user_id=query.get("user_id"), phone_device_id=query.get("phone_device_id"))}
            if len(segments) == 4 and segments[3] == "replies" and method == "GET":
                if not query.get("user_id") or not query.get("phone_device_id"):
                    raise UnauthorizedError("eavesdrop read requires user_id and phone_device_id")
                return 200, {}, {"items": self.store.list_eavesdrop_replies(session_id, user_id=query.get("user_id"), phone_device_id=query.get("phone_device_id"))}
        if segments[:3] == ["v1", "diagnostics", "opt-in"] and method == "POST":
            payload = self._json_body(body)
            event_id = self._json_string(payload, "event_id") if "event_id" in payload and payload["event_id"] is not None else None
            expires_at = self._json_string(payload, "expires_at") if "expires_at" in payload and payload["expires_at"] is not None else None
            enabled = payload.get("enabled", True)
            if not isinstance(enabled, bool):
                raise ValidationError("enabled must be boolean")
            return 201, {}, self.store.record_diagnostics_opt_in(self._json_string(payload, "user_id"), self._json_string(payload, "device_id"), event_id=event_id, enabled=enabled, expires_at=expires_at, now=payload.get("now"))
        if segments[:3] == ["v1", "diagnostics", "events"] and method == "POST":
            payload = self._json_body(body)
            occurred_at = self._json_string(payload, "occurred_at") if "occurred_at" in payload and payload["occurred_at"] is not None else None
            return 201, {}, self.store.ingest_diagnostic_event(self._json_string(payload, "user_id"), self._json_string(payload, "device_id"), event_id=self._json_string(payload, "event_id"), idempotency_key=self._json_string(payload, "idempotency_key"), payload=payload.get("payload", {}), occurred_at=occurred_at, now=payload.get("now"))
        if segments[:3] == ["v1", "diagnostics", "bundles"] and method == "POST":
            payload = self._json_body(body)
            compressed_value = payload.get("compressed_base64")
            if not isinstance(compressed_value, str):
                raise ValidationError("compressed_base64 is required and must be a string")
            try:
                compressed = base64.b64decode(compressed_value, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValidationError("compressed_base64 is invalid") from exc
            expanded_size = self._json_integer(payload, "expanded_size", allow_none=True) if "expanded_size" in payload else None
            return 201, {}, self.store.ingest_diagnostic_bundle(self._json_string(payload, "user_id"), self._json_string(payload, "device_id"), self._json_string(payload, "bundle_id"), compressed, opt_in_event_id=self._json_string(payload, "opt_in_event_id"), expanded_size=expanded_size, now=payload.get("now"))
        if segments[:2] == ["v1", "diagnostics"] and len(segments) == 2 and method == "GET":
            if not query.get("user_id") or not query.get("device_id"):
                raise UnauthorizedError("diagnostics read requires user_id and device_id")
            return 200, {}, self.store.list_diagnostics(query["user_id"], query["device_id"], category=query.get("category"), stage=query.get("stage"), limit=self._query_integer(query, "limit", default=100, minimum=1, maximum=500) or 100)
        if segments[:3] == ["v1", "diagnostics", "export"] and method == "GET":
            if not query.get("user_id") or not query.get("device_id"):
                raise UnauthorizedError("diagnostics export requires user_id and device_id")
            return 200, {}, self.store.export_diagnostics(query["user_id"], query["device_id"])
        if segments[:3] == ["v1", "diagnostics", "delete"] and method == "POST":
            payload = self._json_body(body)
            return 200, {}, self.store.delete_diagnostics(str(payload["user_id"]), str(payload["device_id"]), now=payload.get("now"))
        if segments[:2] == ["v1", "diagnostics"] and len(segments) == 2 and method == "DELETE":
            payload = self._json_body(body) if body else {}
            user_id = query.get("user_id") or payload.get("user_id")
            device_id = query.get("device_id") or payload.get("device_id")
            if not user_id or not device_id:
                raise UnauthorizedError("diagnostics deletion requires user_id and device_id")
            return 200, {}, self.store.delete_diagnostics(str(user_id), str(device_id), now=query.get("now") or payload.get("now"))
        if segments[:3] == ["v1", "internal", "schedule_create"] and method == "POST":
            if self._header_value(headers, "X-Recorder-Internal-Trusted") != "1":
                raise UnauthorizedError("schedule_create requires the trusted Recorder adapter")
            return 201, {}, self.schedule_create(self._json_body(body))
        if segments[:3] == ["v1", "internal", "scheduler"] and len(segments) == 4 and segments[3] == "fire" and method == "POST":
            payload = self._json_body(body)
            owner = self._json_string(payload, "owner") if "owner" in payload else "scheduler-1"
            lease_seconds = self._json_integer(payload, "lease_seconds") if "lease_seconds" in payload else 30
            limit = self._json_integer(payload, "limit") if "limit" in payload else 50
            assert lease_seconds is not None and limit is not None
            items = self.run_scheduler(
                owner=owner,
                lease_seconds=lease_seconds,
                limit=limit,
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
            return 201, {}, self.store.register_device(self._json_string(payload, "user_id"), self._json_string(payload, "device_id"), self._json_string(payload, "kind"))
        if segments[:2] == ["v1", "devices"] and len(segments) == 4 and segments[3] == "revoke" and method == "POST":
            payload = self._json_body(body)
            user_id = self._json_string(payload, "user_id")
            self.store.revoke_device(user_id, segments[2])
            return 200, {}, self.store.get_device(user_id, segments[2])
        if segments[:2] == ["v1", "turns"] and len(segments) == 2 and method == "POST":
            payload = self._json_body(body)
            if "text" in payload and not payload.get("parts"):
                if not isinstance(payload["text"], str):
                    raise ValidationError("text must be a JSON string")
                manifest = {key: value for key, value in payload.items() if key != "text"}
                return 202, {}, self.accept_text_turn(manifest, payload["text"])
            return 201, {}, self.store.create_turn(payload)
        if segments[:2] == ["v1", "turns"] and len(segments) == 4 and segments[3] == "accept" and method == "POST":
            return 200, {}, self.accept_turn(segments[2])
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
                if not segments[6].isdigit():
                    raise ValidationError("chunk sequence must be a non-negative integer")
                sequence = int(segments[6])
                result = self.store.put_chunk(turn_id, part_id, sequence, body, expected_sha256=self._header_value(headers, "X-Chunk-SHA256"))
                return 200, {}, result
            if len(segments) == 6 and segments[5] == "finish" and method == "POST":
                payload = self._json_body(body)
                total_chunks = self._json_integer(payload, "total_chunks")
                total_bytes = self._json_integer(payload, "total_bytes")
                assert total_chunks is not None and total_bytes is not None
                return 200, {}, self.store.finish_part(
                    turn_id,
                    part_id,
                    total_chunks=total_chunks,
                    total_bytes=total_bytes,
                    whole_stream_sha256=payload["whole_stream_sha256"],
                    duration_ms=self._json_integer(payload, "duration_ms", allow_none=True) if "duration_ms" in payload else None,
                )
        if len(segments) in {5, 6} and segments[:2] == ["v1", "turns"] and segments[3] == "events" and (len(segments) == 5 or segments[5] == "ack") and method == "POST":
            payload = self._json_body(body)
            event_version = self._json_integer(payload, "event_version")
            assert event_version is not None
            return 200, {}, self.store.ack_event(segments[2], segments[4], device_id=self._json_string(payload, "device_id"), event_version=event_version, payload_sha256=self._json_string(payload, "payload_sha256"))
        if segments[:2] == ["v1", "outbox"] and method == "GET":
            return 200, {}, {"items": self.store.pending_outbox(query["device_id"], limit=self._query_integer(query, "limit", default=50, minimum=1, maximum=500) or 50)}
        if len(segments) == 4 and segments[:2] == ["v1", "tts"] and segments[3] == "bridge-read" and method == "GET":
            bridge_device_id = query.get("device_id")
            if not bridge_device_id:
                raise ValidationError("device_id is required for TTS bridge reads")
            metadata, audio = self.store.read_tts_for_bridge(segments[2], bridge_device_id=bridge_device_id)
            metadata["audio_base64"] = base64.b64encode(audio).decode("ascii")
            return 200, {}, metadata
        if segments[:2] == ["v1", "tts"] and len(segments) == 3 and method == "GET":
            device_id = query.get("device_id") or self._header_value(headers, "X-Recorder-Device-ID")
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
            return 200, {}, self.store.relay_tts_received(segments[2], device_id=self._json_string(payload, "device_id"), payload_sha256=self._json_string(payload, "payload_sha256"))
        if segments[:2] == ["v1", "projects"] and len(segments) == 2:
            if method == "GET":
                return 200, {}, {"items": self.store.list_projects(query["user_id"], include_archived=query.get("include_archived") == "true")}
            if method == "POST":
                payload = self._json_body(body)
                optional_string = lambda key: self._json_string(payload, key) if key in payload and payload[key] is not None else None
                return 201, {}, self.store.create_project(self._json_string(payload, "user_id"), project_number=self._json_string(payload, "project_number"), name=self._json_string(payload, "name"), aliases=payload.get("aliases"), description=payload.get("description", ""), idempotency_key=optional_string("idempotency_key"))
        if segments[:3] == ["v1", "projects", "search"] and method == "GET":
            return 200, {}, {"items": self.store.search_projects(query["user_id"], query.get("q", ""), include_archived=query.get("include_archived") == "true")}
        if segments[:2] == ["v1", "projects"] and len(segments) >= 3:
            project_id = segments[2]
            if len(segments) == 3 and method == "GET":
                return 200, {}, self.store.get_project(query["user_id"], project_id, include_archived=True)
            if len(segments) == 3 and method == "PATCH":
                payload = self._json_body(body)
                expected_version = self._json_integer(payload, "expected_version")
                assert expected_version is not None
                patch = dict(payload)
                patch.pop("expected_version", None)
                return 200, {}, self.store.update_project(query["user_id"], project_id, expected_version=expected_version, patch=patch)
            if len(segments) == 4 and segments[3] == "archive" and method == "POST":
                payload = self._json_body(body)
                expected_version = self._json_integer(payload, "expected_version")
                assert expected_version is not None
                return 200, {}, self.store.archive_project(query["user_id"], project_id, expected_version=expected_version)
        if segments[:2] == ["v1", "turns"] and len(segments) == 4 and segments[3] == "archive" and method == "POST":
            payload = self._json_body(body)
            source = payload.get("source", "api")
            if not isinstance(source, str) or not source:
                raise ValidationError("source must be a non-empty string")
            return 200, {}, self.store.archive_turn(query["user_id"], segments[2], source=source)
        if segments[:3] == ["v1", "internal", "router"] and method == "POST":
            payload = self._json_body(body)
            owner = self._json_string(payload, "owner") if "owner" in payload else "router-1"
            return 200, {}, self.route_next(self._json_string(payload, "user_id"), owner)
        if segments[:3] == ["v1", "internal", "hermes"] and method == "POST":
            payload = self._json_body(body)
            owner = self._json_string(payload, "owner") if "owner" in payload else "hermes-1"
            return 200, {}, self.process_next_hermes(self._json_string(payload, "session_id"), owner)
        if segments[:3] == ["v1", "internal", "tts"] and method == "POST":
            payload = self._json_body(body)
            limit = self._json_integer(payload, "limit") if "limit" in payload else 50
            assert limit is not None
            return 200, {}, self.generate_pending_tts(limit=limit)
        raise NotFoundError("API route not found")


def create_service(db_path: str, storage_root: str, *, clock: Any | None = None, **kwargs: Any) -> RecorderService:
    kwargs.setdefault("asr_fallback_order", ())
    return RecorderService(RecorderStore(db_path, storage_root=storage_root, clock=clock), **kwargs)


def create_configured_service(config: "RecorderConfig") -> RecorderService:
    from .config import ProviderConfig, RecorderConfig

    if not isinstance(config, RecorderConfig):
        raise TypeError("config must be RecorderConfig")
    from .adapters import CredentialError, HttpHermesGateway

    def build_named_provider(declaration: Any, kind: str) -> ASRProvider | TTSProvider | None:
        adapter = str(declaration.adapter).lower()
        if not declaration.enabled or adapter in {"", "disabled", "none", "off"}:
            return None
        if adapter in {"fixture", "static", "test"}:
            raise CredentialError("fixture providers are test-only")
        endpoint = declaration.endpoint
        credential_file = declaration.credential_file
        if adapter in {"hermes", "hermes-default"}:
            endpoint = endpoint or config.hermes_base_url
            credential_file = credential_file or config.hermes_api_key_file
            if not endpoint or not credential_file:
                raise CredentialError("configured Hermes provider requires endpoint and credential file")
            profile = declaration.profile if declaration.profile != "default" else config.hermes_profile
            if kind == "asr":
                return HermesAudioASRProvider(endpoint, profile=profile, timeout=declaration.timeout_seconds, credential_file=credential_file, max_bytes=declaration.max_bytes, health_path=declaration.health_path, capability_path=declaration.capability_path)
            return HermesAudioTTSProvider(endpoint, profile=profile, timeout=declaration.timeout_seconds, credential_file=credential_file, max_bytes=declaration.max_bytes, health_path=declaration.health_path, capability_path=declaration.capability_path)
        if not endpoint:
            raise CredentialError("configured provider endpoint is required")
        if kind == "asr":
            if not declaration.model:
                raise CredentialError("configured ASR provider model is required")
            provider_type = NemotronASRProvider if adapter == "nemotron" else WhisperASRProvider if adapter in {"whisper", "whisper-compatible"} else HttpASRProvider
            return provider_type(endpoint, model=declaration.model, timeout=declaration.timeout_seconds, credential_file=credential_file, language=declaration.language, max_bytes=declaration.max_bytes, media_types=declaration.media_types, health_path=declaration.health_path, capability_path=declaration.capability_path)
        if not declaration.model or not declaration.voice:
            raise CredentialError("configured TTS provider model and voice are required")
        provider_type = EdgeTTSProvider if adapter in {"edge", "edge-tts"} else HttpTTSProvider
        return provider_type(endpoint, model=declaration.model, voice=declaration.voice, timeout=declaration.timeout_seconds, credential_file=credential_file, language=declaration.language, max_bytes=declaration.max_bytes, rate=declaration.rate, pitch=declaration.pitch, volume=declaration.volume, output_format=declaration.output_format or "mp3", options={key: value for key, value in declaration.options}, health_path=declaration.health_path, capability_path=declaration.capability_path)

    def build_named_chain(kind: str, declarations: tuple[Any, ...], names: tuple[str, ...], deadline: float) -> ProviderChain | None:
        if not declarations:
            if names:
                raise CredentialError(f"{kind} chain refers to an unknown provider")
            return None
        by_name = {item.name: item for item in declarations}
        order = tuple(names)
        if not order:
            return None
        targets: list[ProviderTarget] = []
        for name in order:
            declaration = by_name.get(name)
            if declaration is None:
                raise CredentialError(f"{kind} chain refers to an unknown provider")
            provider = build_named_provider(declaration, kind)
            if provider is None:
                raise CredentialError(f"{kind} chain includes a disabled provider")
            declared = declaration.safe_dict()
            if declaration.endpoint is None and kind in {"asr", "tts"} and config.hermes_base_url and declaration.adapter in {"hermes", "hermes-default"}:
                declared["endpoint"] = config.hermes_base_url
            targets.append(ProviderTarget(name, kind, declaration.adapter, provider, retries=declaration.retries, timeout_seconds=declaration.timeout_seconds, declared=declared))
        return ProviderChain(kind, targets, overall_deadline_seconds=deadline)

    asr_declarations = tuple(getattr(config, "asr_providers", ()))
    tts_declarations = tuple(getattr(config, "tts_providers", ()))
    asr_global_names = tuple(getattr(config, "asr_chain", ()))
    tts_global_names = tuple(getattr(config, "tts_chain", ()))
    if not asr_declarations and not asr_global_names and config.asr_source == "hermes" and config.hermes_base_url and config.hermes_api_key_file:
        asr_declarations = (
            ProviderConfig.from_spec(
                "hermes-default",
                "asr",
                {"adapter": "hermes", "endpoint": config.hermes_base_url, "profile": config.hermes_profile, "credential_file": config.hermes_api_key_file, "enabled": True},
            ),
        )
        asr_global_names = ("hermes-default",)
    if not tts_declarations and not tts_global_names and config.tts_source == "hermes" and config.hermes_base_url and config.hermes_api_key_file:
        tts_declarations = (
            ProviderConfig.from_spec(
                "hermes-default",
                "tts",
                {"adapter": "hermes", "endpoint": config.hermes_base_url, "profile": config.hermes_profile, "credential_file": config.hermes_api_key_file, "enabled": True},
            ),
        )
        tts_global_names = ("hermes-default",)
    asr_overrides = dict(getattr(config, "asr_overrides", ()))
    tts_overrides = dict(getattr(config, "tts_overrides", ()))
    configured_asr_chain = build_named_chain("asr", asr_declarations, tuple(asr_overrides.get("global", asr_global_names)), getattr(config, "asr_deadline_seconds", 60.0))
    configured_tts_chain = build_named_chain("tts", tts_declarations, tuple(tts_overrides.get("global", tts_global_names)), getattr(config, "tts_deadline_seconds", 60.0))
    scoped_asr_chains = {scope: build_named_chain("asr", asr_declarations, tuple(names), getattr(config, "asr_deadline_seconds", 60.0)) for scope, names in asr_overrides.items() if scope != "global"}
    scoped_tts_chains = {scope: build_named_chain("tts", tts_declarations, tuple(names), getattr(config, "tts_deadline_seconds", 60.0)) for scope, names in tts_overrides.items() if scope != "global"}
    if any(chain is None for chain in scoped_asr_chains.values()) or any(chain is None for chain in scoped_tts_chains.values()):
        raise CredentialError("provider overrides must select a usable chain")

    def build_asr(name: str, endpoint: str | None, model: str | None, credential_file: str | None) -> ASRProvider | None:
        normalized = name.strip().lower()
        if normalized in {"", "disabled", "none", "off"}:
            return None
        if normalized in {"fixture", "static", "test"}:
            raise CredentialError("fixture ASR providers are test-only")
        if normalized in {"hermes", "hermes-default", "hermes_profile"}:
            # A bare RecorderConfig is a safe, local-disabled configuration.
            # Once either half of the inherited Hermes contract is supplied,
            # both halves are mandatory and are validated before the store is
            # opened so a bad deployment cannot create state as a side effect.
            if not config.hermes_base_url and not config.hermes_api_key_file:
                return None
            if not config.hermes_base_url or not config.hermes_api_key_file:
                raise CredentialError("Hermes ASR requires hermes_base_url and credential file")
            return HermesAudioASRProvider(
                config.hermes_base_url,
                profile=config.hermes_profile,
                timeout=config.asr_provider_timeout_seconds,
                credential_file=config.hermes_api_key_file,
            )
        if normalized in {"nemotron"}:
            provider_type = NemotronASRProvider
        elif normalized in {"whisper", "whisper-compatible"}:
            provider_type = WhisperASRProvider
        elif normalized in {"http", "http-asr", "remote", "openai-compatible"}:
            provider_type = HttpASRProvider
        else:
            raise CredentialError("unsupported ASR provider")
        if not endpoint or not model:
            raise CredentialError("ASR provider endpoint and model are required")
        return provider_type(endpoint, model=model, timeout=config.asr_provider_timeout_seconds, credential_file=credential_file)

    asr_providers: dict[str, ASRProvider] = {}
    if not asr_declarations:
        realtime_name = config.realtime_asr_provider
        if config.asr_mode and realtime_name == "hermes":
            realtime_name = config.asr_mode
        elif config.asr_source != "hermes" and realtime_name == "hermes":
            realtime_name = config.asr_source
        for stage, name, endpoint, model, credential_file in (
            ("realtime", realtime_name, config.realtime_asr_endpoint, config.realtime_asr_model, config.realtime_asr_credential_file),
            ("batch", config.batch_asr_provider, config.batch_asr_endpoint, config.batch_asr_model, config.batch_asr_credential_file),
            ("local", config.local_asr_provider, config.local_asr_endpoint, config.local_asr_model, config.local_asr_credential_file),
        ):
            provider = build_asr(name, endpoint, model, credential_file)
            if provider is not None:
                asr_providers[stage] = provider

    tts_name = "disabled" if tts_declarations else config.tts_provider.strip().lower()
    if config.tts_mode and tts_name == "hermes":
        tts_name = config.tts_mode.strip().lower()
    elif config.tts_source != "hermes" and tts_name == "hermes":
        tts_name = config.tts_source.strip().lower()
    if tts_name in {"fixture", "static", "test"}:
        raise CredentialError("fixture TTS providers are test-only")
    if tts_name in {"", "disabled", "none", "off"}:
        tts: TTSProvider = DisabledTTSProvider()
    elif tts_name in {"hermes", "hermes-default", "hermes_profile"}:
        if not config.hermes_base_url and not config.hermes_api_key_file:
            tts = DisabledTTSProvider()
        else:
            if not config.hermes_base_url or not config.hermes_api_key_file:
                raise CredentialError("Hermes TTS requires hermes_base_url and credential file")
            tts = HermesAudioTTSProvider(
                config.hermes_base_url,
                profile=config.hermes_profile,
                timeout=config.tts_timeout_seconds,
                credential_file=config.hermes_api_key_file,
            )
    else:
        if tts_name not in {"http", "http-tts", "remote", "openai-compatible", "edge", "edge-tts"}:
            raise CredentialError("unsupported TTS provider")
        if not config.tts_endpoint or not config.tts_model or not config.tts_voice:
            raise CredentialError("TTS endpoint, model, and voice are required")
        tts_type = EdgeTTSProvider if tts_name in {"edge", "edge-tts"} else HttpTTSProvider
        tts = tts_type(
            config.tts_endpoint,
            model=config.tts_model,
            voice=config.tts_voice,
            timeout=config.tts_timeout_seconds,
            credential_file=config.tts_credential_file,
        )

    # Construct the credential-bearing Hermes gateway before creating the
    # SQLite store.  HttpHermesGateway reads and validates the credential once;
    # a missing/unsafe credential therefore has zero local state mutation.
    hermes = None
    if config.hermes_base_url or config.hermes_api_key_file:
        if not config.hermes_base_url or not config.hermes_api_key_file:
            raise CredentialError("Hermes API credential path and endpoint are required")
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
        diagnostics_max_compressed_bytes=config.diagnostics_max_compressed_bytes,
        diagnostics_max_expanded_bytes=config.diagnostics_max_expanded_bytes,
        diagnostics_retention_seconds=config.diagnostics_retention_seconds,
        tts_artifact_ttl_seconds=config.tts_artifact_ttl_seconds,
    )
    if hermes is not None:
        hermes._attachment_resolver = store.resolve_attachment_reference
    return RecorderService(
        store,
        hermes=hermes,
        asr_providers=asr_providers,
        tts=(configured_tts_chain.targets[0].provider if configured_tts_chain is not None else tts),
        asr_chain=configured_asr_chain,
        tts_chain=configured_tts_chain,
        asr_chains={scope: chain for scope, chain in scoped_asr_chains.items() if chain is not None},
        tts_chains={scope: chain for scope, chain in scoped_tts_chains.items() if chain is not None},
        asr_fallback_order=config.asr_fallback_order,
        hermes_max_attempts=config.hermes_max_attempts,
        hermes_grace_seconds=config.hermes_grace_seconds,
    )
