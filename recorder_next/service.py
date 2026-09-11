from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import inspect
import json
import logging
import math
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, replace
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, unquote, urlsplit

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
from .api_models import WORKER_CLAIM, WORKER_COMPLETE, WORKER_FAIL, WORKER_RECOVER, WORKER_RUN
from .canonical import hermes_content_hash, normalize_hermes_text
from .config import RecorderConfig
from .errors import ForbiddenError, GatewayRequestTooLargeError, LeaseConflict, NotFoundError, RecorderError, ServiceStoppingError, UnauthorizedError, UnsupportedMediaType, ValidationError
from .features import DurableWorker, ManagedFileBody
from .hermes_wire import GatewayRequestTooLarge, SubmissionContext, WirePolicy, estimate_run_body_upper_bound, serialize_json
from .http_contract import match_operation, project_response, validate_request, validate_request_headers, validate_response
from .ingress_contract import strict_json_loads
from .media import MediaValidationError, validate_wav
from .models import AsrResult, HermesResult, RouterDecision, TTSResult
from .store import DEFAULT_MISSING_PAGE_SIZE, MAX_MISSING_PAGE_SIZE, FINAL_ERROR_MESSAGES, RecorderStore


logger = logging.getLogger(__name__)


class VoiceNotReadyError(RecorderError):
    code = "VOICE_NOT_READY"
    status = 500
    default_message = "voice service is not ready"


class RecorderService:
    """Application service coordinating adapters around RecorderStore."""

    _HERMES_INPUT_ERROR = "첨부 파일 형식이 현재 Hermes 입력 계약과 호환되지 않습니다. 원본은 보존되어 다시 시도할 수 있습니다."

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
        ingress_secret: str | None = None,
        internal_worker_principals: Sequence[tuple[str, str]] = (),
        gateway_max_request_bytes: int = 10_000_000,
        production_readiness: Mapping[str, bool] | None = None,
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
        configured_ingress_secret = ingress_secret if ingress_secret is not None else os.environ.get("RECORDER_INGRESS_SECRET")
        self._ingress_secret = configured_ingress_secret if isinstance(configured_ingress_secret, str) and configured_ingress_secret else None
        self._internal_worker_principals = frozenset((str(user), str(device)) for user, device in internal_worker_principals)
        self._wire_policy = WirePolicy(gateway_max_request_bytes=gateway_max_request_bytes)
        self._lock = threading.RLock()
        self._drain_condition = threading.Condition(self._lock)
        self._active_operations = 0
        self._lifecycle_state = "RUNNING"
        self._background_stop: threading.Event | None = None
        self._background_threads: list[threading.Thread] = []
        self._background_state = {
            "worker": {"started": False, "alive": False, "last_iteration_success": None, "active_deadline": None, "error_streak": 0, "error_category": None},
            "scheduler": {"started": False, "alive": False, "last_iteration_success": None, "active_deadline": None, "error_streak": 0, "error_category": None},
        }
        self._production_readiness = None if production_readiness is None else {
            name: bool(production_readiness.get(name)) for name in ("asr", "tts", "hermes")
        }
        self._shutdown_requested = threading.Event()

    @staticmethod
    def _background_error_category(exc: BaseException) -> str:
        if isinstance(exc, (ProviderFailure, ChainFailure)):
            return "provider"
        if isinstance(exc, sqlite3.Error):
            return "storage"
        if isinstance(exc, LeaseConflict):
            return "lease"
        return "internal"

    def _set_background_state(
        self,
        name: str,
        *,
        started: bool | None = None,
        alive: bool | None = None,
        success: bool | None = None,
        active_deadline: float | None = None,
        error_category: str | None = None,
    ) -> None:
        with self._lock:
            state = self._background_state[name]
            previous_alive = state["alive"]
            previous_success = state["last_iteration_success"]
            if started is not None:
                state["started"] = started
            if alive is not None:
                state["alive"] = alive
            state["active_deadline"] = active_deadline
            if success is True:
                state["last_iteration_success"] = True
                state["error_streak"] = 0
                state["error_category"] = None
            elif success is False:
                state["last_iteration_success"] = False
                state["error_streak"] = min(10, int(state["error_streak"]) + 1)
                state["error_category"] = error_category if error_category in {"provider", "storage", "lease", "internal"} else "internal"
            current_alive = state["alive"]
            current_category = state["error_category"]
            current_streak = state["error_streak"]
        if previous_alive != current_alive:
            logger.info("Recorder background %s alive=%s", name, current_alive)
        if success is False and previous_success is not False:
            logger.warning(
                "Recorder background %s first_failure category=%s streak=%s",
                name,
                current_category,
                current_streak,
            )

    def _voice_ready(self) -> bool:
        with self._lock:
            if self._production_readiness is None:
                return True
            if not all(self._production_readiness.values()):
                return False
            now = time.monotonic()
            for state in self._background_state.values():
                if not state["started"] or not state["alive"] or state["last_iteration_success"] is not True:
                    return False
                deadline = state["active_deadline"]
                if isinstance(deadline, (int, float)) and now > deadline:
                    return False
            return True

    def _set_dependency_availability(self, name: str, available: bool) -> None:
        with self._lock:
            if self._production_readiness is not None and name in self._production_readiness:
                self._production_readiness[name] = bool(available)

    @staticmethod
    def _probe_provider_chain(chain: ProviderChain | None) -> None:
        if chain is None or not chain.targets:
            raise ProviderFailure("capability_unavailable", retryable=False)
        for target in chain.targets:
            provider = target.provider
            readiness_check = getattr(provider, "readiness_check", None)
            if callable(readiness_check):
                readiness_check()
                continue
            health_check = getattr(provider, "health_check", None)
            capability_check = getattr(provider, "capability_check", None)
            if not callable(health_check) or not callable(capability_check):
                raise ProviderFailure("capability_unavailable", retryable=False)
            for result in (health_check(), capability_check()):
                if not isinstance(result, Mapping) or result.get("configured") is False or result.get("ok") is False or result.get("ready") is False:
                    raise ProviderFailure("capability_unavailable", retryable=True)

    def refresh_production_readiness(self) -> bool:
        """Refresh cached dependency availability without running model work."""

        with self._lock:
            if self._production_readiness is None:
                return True
        for name, probe in (
            ("asr", lambda: self._probe_provider_chain(self.asr_chain)),
            ("tts", lambda: self._probe_provider_chain(self.tts_chain)),
            ("hermes", lambda: getattr(self.hermes, "capability_check")()),
        ):
            try:
                probe()
            except Exception:
                self._set_dependency_availability(name, False)
            else:
                self._set_dependency_availability(name, True)
        with self._lock:
            return bool(self._production_readiness and all(self._production_readiness.values()))

    def _begin_operation(self) -> None:
        with self._drain_condition:
            if self._shutdown_requested.is_set():
                raise ServiceStoppingError("Recorder service is draining and is not accepting new work")
            self._active_operations += 1

    def _end_operation(self) -> None:
        with self._drain_condition:
            self._active_operations = max(0, self._active_operations - 1)
            self._drain_condition.notify_all()

    def admit_http(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str],
        *,
        body_length: int,
        peer_addr: tuple[str, int],
    ) -> None:
        """Admit and preflight a request before sending 100 or reading body."""
        self._begin_operation()
        try:
            self.preflight_http(
                method,
                target,
                headers,
                body_length=body_length,
                peer_addr=peer_addr,
            )
        except BaseException:
            self._end_operation()
            raise

    def release_http(self) -> None:
        self._end_operation()

    @property
    def lifecycle_state(self) -> str:
        with self._lock:
            return self._lifecycle_state

    def _mark_stopped_if_idle(self) -> None:
        with self._drain_condition:
            background_alive = any(thread.is_alive() for thread in self._background_threads)
            if self._shutdown_requested.is_set() and self._active_operations == 0 and not background_alive:
                self._lifecycle_state = "STOPPED"
                self._drain_condition.notify_all()

    def wait_for_drain(self, *, timeout: float = 30.0) -> bool:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(float(timeout)) or timeout < 0:
            raise ValueError("timeout must be a non-negative number")
        deadline = time.monotonic() + float(timeout)
        with self._drain_condition:
            while self._active_operations:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._drain_condition.wait(remaining)
        self._mark_stopped_if_idle()
        return True

    @staticmethod
    def _poll_seconds(value: float, field: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or not 0 < float(value) <= 300:
            raise ValueError(f"{field} must be between 0 and 300 seconds")
        return float(value)

    @staticmethod
    def _lease_seconds(value: int, field: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 86400:
            raise ValueError(f"{field} must be between 1 and 86400 seconds")
        return value

    def start_background_workers(
        self,
        *,
        worker_poll_seconds: float = 0.25,
        scheduler_poll_seconds: float = 1.0,
        worker_lease_seconds: int = 30,
        scheduler_lease_seconds: int = 30,
    ) -> None:
        """Start the in-process worker and scheduler lifecycle threads."""

        worker_poll_seconds = self._poll_seconds(worker_poll_seconds, "worker_poll_seconds")
        scheduler_poll_seconds = self._poll_seconds(scheduler_poll_seconds, "scheduler_poll_seconds")
        worker_lease_seconds = self._lease_seconds(worker_lease_seconds, "worker_lease_seconds")
        scheduler_lease_seconds = self._lease_seconds(scheduler_lease_seconds, "scheduler_lease_seconds")
        with self._lock:
            self._background_threads = [thread for thread in self._background_threads if thread.is_alive()]
            if self._background_threads or self._shutdown_requested.is_set():
                return
            stop = threading.Event()
            worker_owner = f"recorder-worker-{uuid.uuid4()}"
            scheduler_owner = f"recorder-scheduler-{uuid.uuid4()}"
            worker = threading.Thread(
                target=self._background_worker_loop,
                args=(stop, worker_owner, worker_poll_seconds, worker_lease_seconds),
                name="recorder-worker",
                daemon=True,
            )
            scheduler = threading.Thread(
                target=self._background_scheduler_loop,
                args=(stop, scheduler_owner, scheduler_poll_seconds, scheduler_lease_seconds),
                name="recorder-scheduler",
                daemon=True,
            )
            self._background_stop = stop
            self._background_threads = [worker, scheduler]
            worker.start()
            scheduler.start()

    def _background_worker_loop(self, stop: threading.Event, owner: str, poll_seconds: float, lease_seconds: int) -> None:
        admitted = False
        self._set_background_state("worker", started=True, alive=True)
        try:
            self._begin_operation()
            admitted = True
            error_streak = 0
            while not stop.is_set():
                self._set_background_state("worker", active_deadline=time.monotonic() + max(5.0, lease_seconds * 2.0))
                try:
                    result = self.run_background_worker_once(owner=owner, lease_seconds=lease_seconds)
                    error_streak = 0
                    self._set_background_state("worker", success=True)
                    delay = poll_seconds if result is None else 0.0
                except ServiceStoppingError:
                    break
                except Exception as exc:
                    error_streak = min(error_streak + 1, 8)
                    self._set_background_state("worker", success=False, error_category=self._background_error_category(exc))
                    delay = min(30.0, max(poll_seconds, poll_seconds * (2 ** error_streak)))
                stop.wait(delay)
        finally:
            self._set_background_state("worker", alive=False)
            if admitted:
                self._end_operation()

    def _background_scheduler_loop(self, stop: threading.Event, owner: str, poll_seconds: float, lease_seconds: int) -> None:
        admitted = False
        self._set_background_state("scheduler", started=True, alive=True)
        try:
            self._begin_operation()
            admitted = True
            error_streak = 0
            while not stop.is_set():
                self._set_background_state("scheduler", active_deadline=time.monotonic() + max(5.0, lease_seconds * 2.0))
                try:
                    self.recover_scheduler()
                    self.store.recover_worker_jobs()
                    self.run_scheduler(owner=owner, lease_seconds=lease_seconds)
                    error_streak = 0
                    self._set_background_state("scheduler", success=True)
                    delay = poll_seconds
                except ServiceStoppingError:
                    break
                except Exception as exc:
                    error_streak = min(error_streak + 1, 8)
                    self._set_background_state("scheduler", success=False, error_category=self._background_error_category(exc))
                    delay = min(30.0, max(poll_seconds, poll_seconds * (2 ** error_streak)))
                stop.wait(delay)
        finally:
            self._set_background_state("scheduler", alive=False)
            if admitted:
                self._end_operation()

    def stop_background_workers(self, *, timeout: float = 10.0) -> bool:
        """Request both lifecycle threads to stop and wait for clean exit."""

        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(float(timeout)) or timeout < 0:
            raise ValueError("timeout must be a non-negative number")
        with self._lock:
            stop = self._background_stop
            threads = list(self._background_threads)
        if stop is None:
            self._mark_stopped_if_idle()
            return True
        stop.set()
        deadline = time.monotonic() + float(timeout)
        for thread in threads:
            remaining = max(0.0, deadline - time.monotonic())
            thread.join(remaining)
        with self._lock:
            self._background_threads = [thread for thread in threads if thread.is_alive()]
            if not self._background_threads:
                self._background_stop = None
            stopped = not self._background_threads
        self._mark_stopped_if_idle()
        return stopped

    def request_shutdown(self) -> None:
        """Request the shared lifecycle stop without waiting in a signal handler."""

        with self._lock:
            self._lifecycle_state = "DRAINING"
            self._shutdown_requested.set()
        with self._lock:
            stop = self._background_stop
        if stop is not None:
            stop.set()

    def start_background_loops(self, **kwargs: Any) -> None:
        self.start_background_workers(**kwargs)

    def stop_background_loops(self, **kwargs: Any) -> None:
        self.stop_background_workers(**kwargs)

    @property
    def background_workers_running(self) -> bool:
        with self._lock:
            return any(thread.is_alive() for thread in self._background_threads)

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

    def route_next(self, user_id: str, owner: str = "router-1", *, expected_turn_id: str | None = None, now: str | None = None, worker_claim: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
        effective_now = self._worker_now(worker_claim, now)
        self._assert_worker_effect(worker_claim, stage="route", turn_id=expected_turn_id, now=effective_now)
        claim = self.store.claim_router(user_id, owner, turn_id=expected_turn_id, now=effective_now)
        if claim is None:
            return None
        turn = claim["turn"]
        self._assert_worker_effect(worker_claim, stage="route", turn_id=str(turn["turn_id"]), now=effective_now)
        projects = self.store.list_projects(user_id)
        try:
            decision = self.router.decide(turn, projects)
        except Exception:
            return self.store.commit_routing_error(turn["turn_id"], owner=owner, worker_claim=worker_claim)
        if decision is None and not turn.get("current_project_number") and not projects:
            self._assert_worker_effect(worker_claim, stage="route", turn_id=str(turn["turn_id"]), now=effective_now)
            auto = self.store.create_project(
                user_id,
                project_number=f"AUTO-{int(turn['accepted_seq']):06d}",
                name=f"Recorder project {int(turn['accepted_seq'])}",
                description="Automatically created by the project router seam",
                idempotency_key=turn["turn_id"],
                worker_claim=worker_claim,
            )
            projects = [auto]
            try:
                decision = self.router.decide(turn, projects)
            except Exception:
                return self.store.commit_routing_error(turn["turn_id"], owner=owner, now=effective_now, worker_claim=worker_claim)
        if decision is None:
            return self.store.commit_routing_error(turn["turn_id"], owner=owner, now=effective_now, worker_claim=worker_claim)
        routed = self.store.commit_route(turn["turn_id"], decision, owner=owner, now=effective_now, worker_claim=worker_claim)
        self._enqueue_hermes_job(routed, now=effective_now, worker_claim=worker_claim)
        return routed

    def route_turn(self, turn_id: str, decision: RouterDecision, *, owner: str | None = None) -> dict[str, Any]:
        routed = self.store.commit_route(turn_id, decision, owner=owner)
        self._enqueue_hermes_job(routed)
        return routed

    def process_eavesdrop_segment(self, session_id: str, segment_sequence: int, *, owner: str = "eavesdrop-1", now: str | None = None, expected_segment_sha256: str | None = None, worker_claim: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
        effective_now = self._worker_now(worker_claim, now)
        session = self.store.get_eavesdrop_session(session_id, now=effective_now)
        self._assert_worker_effect(worker_claim, stage="hermes", now=effective_now)
        if worker_claim is not None:
            claim_payload = worker_claim.get("payload")
            if not isinstance(claim_payload, Mapping) or claim_payload.get("session_id") != session_id or claim_payload.get("segment_sequence") != segment_sequence:
                raise LeaseConflict("worker eavesdrop claim does not match the segment")
        decision = next((item for item in session.get("routing_decisions", []) if item.get("segment_sequence") == segment_sequence), None)
        if decision is None:
            raise ValidationError("eavesdrop routing decision is missing")
        if decision.get("decision") != "FORWARD_DEFAULT" or decision.get("result_state") != "QUEUED":
            return {"session_id": session_id, "segment_sequence": segment_sequence, "state": decision.get("result_state"), "outcome": decision.get("decision"), "reason": decision.get("reason")}
        if session.get("state") != "ACTIVE":
            reason = "session_expired" if session.get("state") == "EXPIRED" else "session_inactive"
            failed = self.store.mark_eavesdrop_decision(session_id, segment_sequence, result_state="FAILED", reason=reason, worker_claim=worker_claim)
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
            self.store.mark_eavesdrop_decision(session_id, segment_sequence, result_state="NO_SPEECH", reason="segment_has_no_transcript", now=effective_now, worker_claim=worker_claim)
            return {"session_id": session_id, "segment_sequence": segment_sequence, "state": "NO_SPEECH"}
        conversation = "\n".join(str(item["transcript"]).strip() for item in segments if isinstance(item.get("transcript"), str) and item["transcript"].strip())
        if not conversation:
            self.store.mark_eavesdrop_decision(session_id, segment_sequence, result_state="NO_SPEECH", reason="conversation_has_no_transcript", now=effective_now, worker_claim=worker_claim)
            return {"session_id": session_id, "segment_sequence": segment_sequence, "state": "NO_SPEECH"}
        try:
            context = self.store.submission_context(str(decision["hermes_submission_id"]))
            if context.subject_kind != "eavesdrop" or context.eavesdrop_session_id != session_id or context.segment_sequence != segment_sequence or context.segment_sha256 != segment.get("sha256"):
                raise ValidationError("eavesdrop submission binding does not match the segment")
            result = self._submit_hermes(
                context=context,
                payload=context.request,
                worker_claim=worker_claim,
            )
            # The run-acceptance callback binds the returned run ID in a
            # separate transaction.  Re-read the immutable context before
            # validating the terminal envelope so eavesdrop forwarding does
            # not compare it with the pre-submit ``run_id=None`` snapshot.
            context = self.store.submission_context(context.submission_id)
        except ValidationError:
            raise
        except Exception as exc:
            raise ProviderFailure("transport", retryable=True) from exc
        result = self._valid_terminal_hermes_result(
            result,
            expected={
                "submission_id": context.submission_id,
                "marker": context.marker,
                "session_key": context.gateway_session_key,
                "run_id": context.run_id,
                "request_sha256": context.canonical_request_sha256,
                "subject_kind": "eavesdrop",
                "eavesdrop_session_id": session_id,
                "segment_sequence": segment_sequence,
                "segment_sha256": segment.get("sha256"),
            },
        )
        if result is None:
            raise ProviderFailure("malformed_response", retryable=False)
        delivered = self.store.commit_eavesdrop_result(
            context.submission_id,
            result,
            worker_claim=worker_claim,
            now=effective_now,
        )
        receipt = delivered.get("effect_receipt_json") or {}
        return {
            "session_id": session_id,
            "segment_sequence": segment_sequence,
            "state": "DELIVERED",
            "reply_id": receipt.get("reply_id") if isinstance(receipt, Mapping) else None,
            "content_hash": hermes_content_hash(result.content),
        }

    @staticmethod
    def _valid_terminal_hermes_result(
        result: Any,
        *,
        expected: Mapping[str, Any],
    ) -> HermesResult | None:
        if not isinstance(result, HermesResult):
            return None
        if result.terminal is not True or not isinstance(result.assistant_message_id, str) or not result.assistant_message_id.strip() or not isinstance(result.content, str) or not result.content.strip():
            return None
        if not isinstance(result.source, str) or not result.source.startswith("hermes"):
            return None
        required = ("submission_id", "marker", "session_key", "run_id", "request_sha256", "subject_kind")
        if any(key not in expected or not isinstance(expected[key], str) or not expected[key] for key in required):
            return None
        if expected["subject_kind"] == "turn":
            if not isinstance(expected.get("turn_id"), str) or not expected["turn_id"]:
                return None
            required = (*required, "turn_id")
        elif expected["subject_kind"] == "eavesdrop":
            if not isinstance(expected.get("eavesdrop_session_id"), str) or not expected["eavesdrop_session_id"] or not isinstance(expected.get("segment_sequence"), int) or isinstance(expected["segment_sequence"], bool) or expected["segment_sequence"] < 0 or not isinstance(expected.get("segment_sha256"), str) or not expected["segment_sha256"]:
                return None
            required = (*required, "eavesdrop_session_id", "segment_sequence", "segment_sha256")
        else:
            return None
        if any(getattr(result, key, None) != expected[key] for key in required):
            return None
        return result

    def _submit_hermes(
        self,
        *,
        context: SubmissionContext,
        payload: Mapping[str, Any],
        owner: str | None = None,
        lease_token: str | None = None,
        worker_claim: Mapping[str, Any] | None = None,
    ) -> HermesResult | None:
        """Submit through the durable run-binding callback, with old-fixture compatibility."""
        submit = self.hermes.submit
        parameters = inspect.signature(submit).parameters

        def bind(run_id: str) -> bool:
            binding_now = worker_claim.get("_worker_now") if isinstance(worker_claim, Mapping) else None
            if context.subject_kind == "turn":
                self.store.bind_hermes_run(
                    context.submission_id,
                    run_id,
                    owner=owner,
                    lease_token=lease_token,
                    worker_claim=worker_claim,
                    now=binding_now if isinstance(binding_now, str) else None,
                )
            else:
                self.store.bind_hermes_run(
                    context.submission_id,
                    run_id,
                    worker_claim=worker_claim,
                    now=binding_now if isinstance(binding_now, str) else None,
                )
            return True

        def project_bound_result(result: Any) -> Any:
            """Attach only the run identity proven by the durable callback.

            Some in-process/test gateways return the terminal content without
            copying the callback context onto their result envelope.  The
            callback has already committed the run binding, so filling only
            absent identity fields is safe; a non-empty conflicting field is
            preserved and will fail the strict validator below.
            """
            if not isinstance(result, HermesResult):
                return result
            bound = self.store.submission_context(context.submission_id)
            expected = {
                "submission_id": bound.submission_id,
                "turn_id": bound.turn_id,
                "marker": bound.marker,
                "session_key": bound.gateway_session_key,
                "run_id": bound.run_id,
                "request_sha256": bound.canonical_request_sha256,
                "subject_kind": bound.subject_kind,
                "eavesdrop_session_id": bound.eavesdrop_session_id,
                "segment_sequence": bound.segment_sequence,
                "segment_sha256": bound.segment_sha256,
            }
            for field, value in expected.items():
                if getattr(result, field, None) is not None and getattr(result, field) != value:
                    return result
            return replace(result, **expected)

        kwargs = {
            "session_key": context.gateway_session_key,
            "request": payload,
            "submission_id": context.submission_id,
            "marker": context.marker,
        }
        if "context" in parameters:
            result = submit(**kwargs, context=context, on_run_accepted=bind)
            return project_bound_result(result) if result is not None else None
        if getattr(self.hermes, "durable_correlation", False):
            raise ValidationError("Hermes adapter does not expose the R25 run-binding contract")
        result = submit(**kwargs)
        if result is None:
            return None
        run_id = result.run_id or f"legacy:{context.submission_id}"
        bind(run_id)
        return HermesResult(
            result.assistant_message_id,
            result.content,
            result.terminal,
            result.source,
            submission_id=context.submission_id,
            turn_id=context.turn_id,
            marker=context.marker,
            session_key=context.gateway_session_key,
            run_id=run_id,
            request_sha256=context.canonical_request_sha256,
            subject_kind=context.subject_kind,
            eavesdrop_session_id=context.eavesdrop_session_id,
            segment_sequence=context.segment_sequence,
            segment_sha256=context.segment_sha256,
        )

    def process_next_hermes(
        self,
        session_id: str,
        owner: str = "hermes-1",
        *,
        hermes_submission_id: str | None = None,
        expected_turn_id: str | None = None,
        now: str | None = None,
        lease_seconds: int = 30,
        worker_claim: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if self.hermes is None:
            raise ValidationError("Hermes adapter is not configured")
        effective_now = self._worker_now(worker_claim, now)
        ingress = self.store.claim_session_ingress(
            session_id,
            owner,
            hermes_submission_id=hermes_submission_id,
            now=effective_now,
            lease_seconds=lease_seconds,
        )
        if ingress is None:
            return None
        self._assert_worker_effect(worker_claim, stage="hermes", turn_id=str(ingress["turn_id"]), now=effective_now)
        if expected_turn_id is not None and ingress["turn_id"] != expected_turn_id:
            self.store.release_session_ingress(
                ingress["hermes_submission_id"],
                owner=owner,
                lease_token=ingress["lease_token"],
                now=effective_now,
                worker_claim=worker_claim,
            )
            raise ValidationError("Hermes worker submission is bound to a different turn")
        payload = ingress["payload"]
        payload_turn_id = payload.get("turn_id") if isinstance(payload, Mapping) else None
        if payload_turn_id is not None and payload_turn_id != ingress["turn_id"]:
            self.store.release_session_ingress(
                ingress["hermes_submission_id"],
                owner=owner,
                lease_token=ingress["lease_token"],
                now=effective_now,
                worker_claim=worker_claim,
            )
            raise ValidationError("Hermes ingress payload turn binding is invalid")
        try:
            context = self.store.submission_context(ingress["hermes_submission_id"])
        except Exception as exc:
            self.store.release_session_ingress(
                ingress["hermes_submission_id"],
                owner=owner,
                lease_token=ingress["lease_token"],
                now=effective_now,
                worker_claim=worker_claim,
            )
            raise ValidationError("Hermes submission binding is unavailable") from exc
        if context.turn_id != ingress["turn_id"] or context.gateway_session_key != ingress["gateway_session_key"]:
            self.store.release_session_ingress(
                ingress["hermes_submission_id"],
                owner=owner,
                lease_token=ingress["lease_token"],
                now=effective_now,
                worker_claim=worker_claim,
            )
            raise ValidationError("Hermes submission binding does not match ingress")
        def call_with_ingress_lease(callback: Any) -> Any:
            stop = threading.Event()
            lost = threading.Event()
            interval = max(0.05, min(float(lease_seconds) / 3.0, 5.0))

            def renew() -> None:
                while not stop.wait(interval):
                    try:
                        renewed = self.store.renew_session_ingress(
                            ingress["hermes_submission_id"],
                            owner=owner,
                            lease_token=ingress["lease_token"],
                            lease_seconds=lease_seconds,
                        )
                    except Exception:
                        renewed = False
                    if not renewed:
                        lost.set()
                        return

            thread = threading.Thread(target=renew, name=f"recorder-ingress-heartbeat-{ingress['turn_id'][:12]}", daemon=True)
            thread.start()
            try:
                result = callback()
                if lost.is_set():
                    raise ProviderFailure("lease_lost", retryable=True)
                return result
            finally:
                stop.set()
                thread.join(timeout=max(1.0, min(float(lease_seconds), 5.0)))
        try:
            def submit_hermes() -> Any:
                self._validate_hermes_projection(payload)
                return self._submit_hermes(
                    context=context,
                    payload=payload,
                    owner=owner,
                    lease_token=ingress["lease_token"],
                )
            result = call_with_ingress_lease(submit_hermes)
            if result is not None:
                # The run-binding callback commits the authoritative run ID in
                # its own transaction.  The claimed ingress snapshot above is
                # intentionally pre-submit state, so refresh it before
                # validating the result; otherwise an accepted legacy/memory
                # adapter response is compared with a stale ``run_id=None``
                # and is incorrectly left pending.
                bound_ingress = self.store.get_ingress(ingress["hermes_submission_id"])
                ingress = {**ingress, **bound_ingress}
        except ProviderFailure:
            self._set_dependency_availability("hermes", False)
            result = None
        except ValueError:
            failed = self.store.commit_hermes_error(
                ingress["hermes_submission_id"],
                grace_seconds=0,
                owner=owner,
                lease_token=ingress["lease_token"],
                now=effective_now,
                worker_claim=worker_claim,
                message=self._HERMES_INPUT_ERROR,
            )
            self._enqueue_tts_jobs(ingress["turn_id"], now=effective_now, worker_claim=worker_claim)
            return failed
        except Exception:
            result = None
        result = self._valid_terminal_hermes_result(
            result,
            expected={
                "submission_id": ingress["hermes_submission_id"],
                "turn_id": ingress["turn_id"],
                "marker": ingress["marker"],
                "session_key": ingress["gateway_session_key"],
                "run_id": ingress.get("run_id") or ingress.get("hermes_run_id"),
                "request_sha256": context.canonical_request_sha256,
                "subject_kind": "turn",
            },
        )
        if result is not None:
            self._assert_worker_effect(worker_claim, stage="hermes", turn_id=str(ingress["turn_id"]), now=effective_now)
            combined_content = self._requery_combined_content(ingress, result)
            committed = self.store.commit_hermes_result(
                ingress["hermes_submission_id"],
                result,
                combined_content=combined_content,
                owner=owner,
                lease_token=ingress["lease_token"],
                now=effective_now,
                worker_claim=worker_claim,
            )
            self._enqueue_tts_jobs(ingress["turn_id"], now=effective_now, worker_claim=worker_claim)
            return committed
        if ingress["attempt_count"] >= self.hermes_max_attempts:
            self._assert_worker_effect(worker_claim, stage="hermes", turn_id=str(ingress["turn_id"]), now=effective_now)
            failed = self.store.commit_hermes_error(
                ingress["hermes_submission_id"],
                grace_seconds=self.hermes_grace_seconds,
                owner=owner,
                lease_token=ingress["lease_token"],
                now=effective_now,
                worker_claim=worker_claim,
            )
            self._enqueue_tts_jobs(ingress["turn_id"], now=effective_now, worker_claim=worker_claim)
            return failed
        self._assert_worker_effect(worker_claim, stage="hermes", turn_id=str(ingress["turn_id"]), now=effective_now)
        self.store.release_session_ingress(
            ingress["hermes_submission_id"],
            owner=owner,
            lease_token=ingress["lease_token"],
            now=effective_now,
            worker_claim=worker_claim,
        )
        return self.store.get_turn(ingress["turn_id"])

    def _validate_hermes_projection(self, payload: Mapping[str, Any]) -> None:
        """Reject attachment shapes the downstream Hermes input contract cannot consume."""
        projected = payload.get("request") if isinstance(payload.get("request"), Mapping) else payload
        if not isinstance(projected, Mapping):
            raise ValueError("Hermes request projection must be an object")
        parts = projected.get("parts")
        if parts is None:
            parts = []
        if not isinstance(parts, list):
            raise ValueError("Hermes request parts must be an array")
        image_sizes: list[int] = []
        for part in parts:
            if not isinstance(part, Mapping):
                raise ValueError("Hermes request part must be an object")
            kind = part.get("kind")
            if kind not in {"attachment", "image", "document", "file", "binary"} and not (kind == "text" and not part.get("text")):
                continue
            mime = part.get("mime")
            normalized_mime = mime.split(";", 1)[0].strip().lower() if isinstance(mime, str) else ""
            if kind in {"document", "file", "binary"} or not normalized_mime.startswith("image/"):
                raise ValueError("unsupported Hermes attachment input")
            if part.get("status") != "COMPLETE":
                raise ValueError("incomplete Hermes attachment input")
            declared_bytes = part.get("declared_bytes", part.get("total_bytes"))
            if not isinstance(declared_bytes, int) or isinstance(declared_bytes, bool) or declared_bytes < 0 or declared_bytes > 8 * 1024 * 1024:
                raise ValueError("Hermes image exceeds the configured attachment limit")
            image_sizes.append(declared_bytes)
        estimate = estimate_run_body_upper_bound(
            {"input": projected.get("input") or projected.get("text") or "", "parts": parts},
            image_declared_bytes=image_sizes,
        )
        if estimate > self._wire_policy.gateway_max_request_bytes:
            raise GatewayRequestTooLarge("Hermes request exceeds the configured Gateway limit")

    def _requery_combined_content(
        self,
        ingress: Mapping[str, Any],
        result: HermesResult,
        *,
        deadline_at: float | None = None,
    ) -> str | None:
        turn = self.store.get_turn(ingress["turn_id"])
        if not turn.get("final_event_version") or turn.get("final_content"):
            return None
        history_method = getattr(self.hermes, "history_messages", None)
        if history_method is None:
            return None
        request_sha256 = ingress.get("canonical_request_sha256")
        if not isinstance(request_sha256, str) or not request_sha256:
            try:
                request_sha256 = self.store.submission_context(
                    str(ingress["hermes_submission_id"])
                ).canonical_request_sha256
            except Exception:
                # Compatibility fixtures may provide only an ingress mapping.
                # The envelope hash is not the request fingerprint.
                request_sha256 = result.request_sha256
        if not isinstance(request_sha256, str) or not request_sha256:
            return None
        try:
            if deadline_at is None:
                messages = history_method(
                    session_key=ingress["gateway_session_key"],
                    marker=ingress["marker"],
                )
            else:
                remaining = deadline_at - time.monotonic()
                if remaining <= 0:
                    return None
                try:
                    messages = history_method(
                        session_key=ingress["gateway_session_key"],
                        marker=ingress["marker"],
                        timeout_seconds=remaining,
                    )
                except TypeError as exc:
                    # The production HTTP gateway accepts this keyword. Keep
                    # older in-process fixtures usable when they do not.
                    if "timeout_seconds" not in str(exc):
                        raise
                    messages = history_method(
                        session_key=ingress["gateway_session_key"],
                        marker=ingress["marker"],
                    )
        except Exception:
            return None
        values: list[str] = []
        seen: set[str] = set()
        if turn.get("final_outcome") == "error" and turn.get("final_error_kind") == "hermes":
            fixed = normalize_hermes_text(FINAL_ERROR_MESSAGES["hermes"])
            values.append(fixed)
            seen.add(hermes_content_hash(fixed))
        for item in list(messages or []) + [result]:
            terminal = self._valid_terminal_hermes_result(
                item,
                expected={
                    "submission_id": ingress["hermes_submission_id"],
                    "turn_id": ingress["turn_id"],
                    "marker": ingress["marker"],
                    "session_key": ingress["gateway_session_key"],
                    "run_id": ingress.get("run_id") or ingress.get("hermes_run_id"),
                    "request_sha256": request_sha256,
                    "subject_kind": "turn",
                },
            )
            if terminal is None:
                continue
            text = normalize_hermes_text(terminal.content)
            digest = hermes_content_hash(text)
            if digest not in seen:
                seen.add(digest)
                values.append(text)
        return "\n".join(values) if values else None

    def _assert_worker_effect(
        self,
        worker_claim: Mapping[str, Any] | None,
        *,
        stage: str,
        turn_id: str | None = None,
        now: str | None = None,
    ) -> None:
        effective_now = self._worker_now(worker_claim, now)
        if worker_claim is not None and not self.store.assert_worker_effect_authority(worker_claim, stage=stage, turn_id=turn_id, now=effective_now):
            raise LeaseConflict("worker effect deadline has expired")

    @staticmethod
    def _worker_now(worker_claim: Mapping[str, Any] | None, now: str | None) -> str | None:
        """Use a worker's logical claim clock only when the worker supplied one.

        Public/service callers must not be able to backdate effect fencing by
        passing an arbitrary ``now`` alongside a hand-built claim.  The durable
        worker adds ``_worker_now`` after it has claimed the row; direct callers
        therefore continue to use the store clock for claim authority.
        """
        if worker_claim is None:
            return now
        claimed_now = worker_claim.get("_worker_now")
        return claimed_now if isinstance(claimed_now, str) and claimed_now else None

    def _commit_unsupported_audio(
        self,
        turn: Mapping[str, Any],
        *,
        worker_claim: Mapping[str, Any] | None = None,
        detail: str | None = None,
    ) -> dict[str, Any]:
        del detail
        turn_id = str(turn["turn_id"])
        generation = int(turn["asr_generation"])
        self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
        next_generation = self.store.set_asr_stage(
            turn_id,
            expected_generation=generation,
            stage="media-validation",
            worker_claim=worker_claim,
        )
        if next_generation is None:
            return self.store.get_turn(turn_id)
        result = AsrResult(
            "PROVIDER_ERROR",
            detail="unsupported_media",
            metadata={
                "error_kind": "unsupported_media",
                "media_revision": "wav-pcm-s16le-16k-mono-v1",
            },
        )
        self.store.commit_asr_result(
            turn_id,
            expected_generation=next_generation,
            stage="media-validation",
            result=result,
            authoritative=True,
            worker_claim=worker_claim,
        )
        self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
        self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"], worker_claim=worker_claim)
        return self.store.get_turn(turn_id)

    def run_asr(self, turn_id: str, *, frozen: Mapping[str, Any] | None = None, worker_claim: Mapping[str, Any] | None = None) -> dict[str, Any]:
        self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
        turn = self.store.get_turn(turn_id)
        if turn.get("authoritative_asr_outcome"):
            return turn
        audio_parts = [part for part in turn["parts"] if part["kind"] == "audio"]
        if not audio_parts:
            return turn
        if len(audio_parts) != 1:
            return self._commit_unsupported_audio(turn, worker_claim=worker_claim, detail="exactly one audio part is required")
        audio_part = audio_parts[0]
        audio_bytes = self.store.read_part(turn_id, audio_part["part_id"])
        try:
            audio = validate_wav(
                audio_bytes,
                part_id=str(audio_part["part_id"]),
                mime=str(audio_part["mime"]),
                duration_ms=audio_part.get("duration_ms"),
            )
        except (MediaValidationError, TypeError, ValueError) as exc:
            return self._commit_unsupported_audio(turn, worker_claim=worker_claim, detail=str(exc))
        chain = self._chain_for_turn("asr", turn)
        if chain is not None:
            generation = int(turn["asr_generation"])
            self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
            next_generation = self.store.set_asr_stage(turn_id, expected_generation=generation, stage="provider-chain", worker_claim=worker_claim)
            if next_generation is None:
                return self.store.get_turn(turn_id)
            try:
                result = chain.execute_asr(audio, turn_id=turn_id, frozen=frozen)
            except ChainFailure as exc:
                self._set_dependency_availability("asr", False)
                result = AsrResult(
                    "PROVIDER_ERROR",
                    detail=exc.kind,
                    metadata={
                        "chain_generation": chain.generation,
                        "chain_fingerprint": chain.fingerprint,
                        "statuses": [dict(item) for item in exc.statuses],
                    },
                )
                self.store.commit_asr_result(
                    turn_id,
                    expected_generation=next_generation,
                    stage="provider-chain",
                    result=result,
                    authoritative=not exc.retryable,
                    worker_claim=worker_claim,
                )
                if exc.retryable:
                    raise ProviderFailure(exc.kind, retryable=True) from exc
                self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
                self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"], worker_claim=worker_claim)
                return self.store.get_turn(turn_id)
            committed_ok = self.store.commit_asr_result(turn_id, expected_generation=next_generation, stage="provider-chain", result=result, worker_claim=worker_claim)
            if not committed_ok:
                return self.store.get_turn(turn_id)
            committed = self.store.get_turn(turn_id)
            if result.outcome == "VALID_TRANSCRIPT":
                self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
                self._enqueue_turn_stage(committed, worker_claim=worker_claim)
            return committed
        stage_order = list(self.asr_fallback_order)
        if not stage_order:
            self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
            self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"], worker_claim=worker_claim)
            return self.store.get_turn(turn_id)
        generation = int(turn["asr_generation"])
        for index, stage in enumerate(stage_order):
            current = self.store.get_turn(turn_id)
            if current["authoritative_asr_outcome"]:
                return current
            self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
            next_generation = self.store.set_asr_stage(turn_id, expected_generation=generation, stage=stage, worker_claim=worker_claim)
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
                if not self.store.commit_asr_result(turn_id, expected_generation=next_generation, stage=stage, result=result, worker_claim=worker_claim):
                    return self.store.get_turn(turn_id)
                return self.store.get_turn(turn_id)
            if result.outcome == "VALID_TRANSCRIPT":
                if not self.store.commit_asr_result(turn_id, expected_generation=next_generation, stage=stage, result=result, worker_claim=worker_claim):
                    return self.store.get_turn(turn_id)
                committed = self.store.get_turn(turn_id)
                self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
                self._enqueue_turn_stage(committed, worker_claim=worker_claim)
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
                    worker_claim=worker_claim,
                )
                self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
                self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"], worker_claim=worker_claim)
                return self.store.get_turn(turn_id)
            if index < len(stage_order) - 1:
                self.store.commit_asr_result(
                    turn_id,
                    expected_generation=next_generation,
                    stage=stage,
                    result=result,
                    authoritative=False,
                    worker_claim=worker_claim,
                )
                generation = next_generation
                continue
            self.store.commit_asr_result(
                turn_id,
                expected_generation=next_generation,
                stage=stage,
                result=result,
                authoritative=provider_failure is None or not provider_failure.retryable,
                worker_claim=worker_claim,
            )
            if provider_failure is not None and provider_failure.retryable:
                raise provider_failure
            self._assert_worker_effect(worker_claim, stage="asr", turn_id=turn_id)
            self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"], worker_claim=worker_claim)
            return self.store.get_turn(turn_id)
        return self.store.get_turn(turn_id)

    def generate_tts(self, artifact_id: str, *, frozen: Mapping[str, Any] | None = None, worker_claim: Mapping[str, Any] | None = None) -> dict[str, Any]:
        artifact = self.store.get_artifact(artifact_id)
        self._assert_worker_effect(worker_claim, stage="tts", turn_id=str(artifact["turn_id"]))
        if artifact["status"] in {"READY", "DELIVERY_PENDING", "PLAYED", "EXPIRED"}:
            return artifact
        try:
            turn = self.store.get_turn(artifact["turn_id"])
            chain = self._chain_for_turn("tts", turn)
            self._assert_worker_effect(worker_claim, stage="tts", turn_id=str(artifact["turn_id"]))
            if chain is not None:
                result = chain.execute_tts(artifact["source_text"], artifact_id=artifact_id, frozen=frozen)
            else:
                result = self.tts.synthesize(artifact["source_text"], artifact_id=artifact_id)
        except ChainFailure as exc:
            self._set_dependency_availability("tts", False)
            status_code = next(
                (
                    item.get("status_code")
                    for item in reversed(exc.statuses)
                    if isinstance(item, Mapping) and item.get("status_code") is not None
                ),
                None,
            )
            if exc.retryable:
                raise ProviderFailure(exc.kind, retryable=True, status_code=status_code) from exc
            return self.store.set_tts_result(
                artifact_id,
                None,
                error=exc.kind,
                error_metadata={"status_code": status_code},
                worker_claim=worker_claim,
            )
        except ProviderFailure as exc:  # provider failures stay separate from text FINAL
            self._set_dependency_availability("tts", False)
            if exc.retryable:
                raise
            return self.store.set_tts_result(
                artifact_id,
                None,
                error=exc.kind,
                error_metadata={"status_code": exc.status_code},
                worker_claim=worker_claim,
            )
        except Exception:  # provider failures stay separate from text FINAL
            return self.store.set_tts_result(artifact_id, None, error="provider_error", worker_claim=worker_claim)
        return self.store.set_tts_result(artifact_id, result, worker_claim=worker_claim)

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

    def get_ingress_for_turn(self, turn_id: str) -> dict[str, Any] | None:
        return self.store.get_ingress_for_turn(turn_id)

    def schedule_create(
        self,
        command: Mapping[str, Any],
        *,
        principal: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        if principal is None:
            return self.schedule_adapter.schedule_create(command)
        return self.schedule_adapter.schedule_create(command, principal=principal)

    def run_scheduler(
        self,
        *,
        owner: str = "scheduler-1",
        lease_seconds: int = 30,
        limit: int = 50,
        now: str | None = None,
    ) -> list[dict[str, Any]]:
        fired = self.store.fire_due_schedules(owner=owner, lease_seconds=lease_seconds, limit=limit, now=now)
        try:
            # Firing and worker-job projection use separate store
            # transactions.  Preserve a fired occurrence for reconciliation,
            # but make transient SQLite failures retryable to the durable
            # scheduler instead of permanently acknowledging the gap.
            self._enqueue_pending_tts_jobs(now=now, scheduled_only=True)
        except sqlite3.DatabaseError as exc:
            raise ProviderFailure("transport", retryable=True) from exc
        return fired

    def recover_scheduler(self, *, now: str | None = None) -> dict[str, Any]:
        result = self.store.recover(now=now)
        reconciled = 0
        for turn in self.store.list_accepted_turns():
            if self._enqueue_turn_stage(turn, now=now) is not None:
                reconciled += 1
        try:
            jobs = self._enqueue_pending_tts_jobs(now=now, scheduled_only=True)
        except sqlite3.DatabaseError as exc:
            raise ProviderFailure("transport", retryable=True) from exc
        result["tts_jobs_enqueued"] = len(jobs)
        result["accepted_turns_reconciled"] = reconciled
        return result

    def _enqueue_stage_job(
        self,
        stage: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
        provider_chain: ProviderChain | None = None,
        now: str | None = None,
        worker_claim: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        effective_now = self._worker_now(worker_claim, now)
        return self.store.enqueue_worker_job(
            kind=stage,
            stage=stage,
            payload=dict(payload),
            idempotency_key=idempotency_key,
            max_attempts=self.hermes_max_attempts if stage == "hermes" else 3,
            now=effective_now,
            provider_chain=provider_chain,
            worker_claim=worker_claim,
            worker_stage=(str(worker_claim.get("stage")) if isinstance(worker_claim, Mapping) and isinstance(worker_claim.get("stage"), str) else None),
            deadline_seconds=(
                max(1, int(math.ceil(provider_chain.overall_deadline_seconds)))
                if provider_chain is not None
                else (180 if stage in {"asr", "tts"} else 300)
            ),
        )

    def _enqueue_turn_stage(self, turn: Mapping[str, Any], *, now: str | None = None, worker_claim: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
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
            worker_claim=worker_claim,
        )

    def _enqueue_hermes_job(self, turn: Mapping[str, Any], *, now: str | None = None, worker_claim: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
        if not turn.get("project_id") or not turn.get("session_key"):
            return None
        ingress = self.store.get_ingress_for_turn(str(turn["turn_id"]))
        if ingress is None:
            if turn.get("state") in {"FINAL_READY", "DELIVERED", "EXPIRED"}:
                return None
            raise ValidationError("Hermes worker projection is missing its durable submission")
        context = self.store.submission_context(str(ingress["hermes_submission_id"]))
        if (
            ingress.get("turn_id") != turn.get("turn_id")
            or ingress.get("target_session_id") != turn.get("project_id")
            or context.gateway_session_key != ingress.get("gateway_session_key")
        ):
            raise ValidationError("Hermes worker projection does not match its durable ingress")
        return self._enqueue_stage_job(
            "hermes",
            {
                "turn_id": turn["turn_id"],
                "session_id": turn["project_id"],
                "hermes_submission_id": ingress["hermes_submission_id"],
            },
            idempotency_key=f"turn:{turn['turn_id']}:hermes",
            now=now,
            worker_claim=worker_claim,
        )

    def _enqueue_pending_tts_jobs(
        self,
        *,
        turn_id: str | None = None,
        now: str | None = None,
        limit: int = 500,
        scheduled_only: bool = False,
        worker_claim: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        # Terminal-row reconciliation is a separate maintenance operation. It
        # is intentionally not piggy-backed on a claimed Hermes effect, whose
        # worker authority is scoped to one turn and one stage.
        if worker_claim is None:
            self.store.reconcile_terminal_tts_jobs(now=now)
        pending_kwargs: dict[str, Any] = {"limit": limit, "include_recording_active": True}
        # Generation is durable work and must not be suppressed by the
        # playback/recording eligibility gate. Delivery remains gated later.
        if scheduled_only:
            # Filter by source in SQL before applying the bounded page.  A
            # large client-originated backlog must not hide scheduled FINALs.
            pending_kwargs["turn_source"] = "server_schedule"
            # A terminal or already-running projection must not consume the
            # whole page forever.  Ask the store for only artifacts without a
            # durable TTS worker projection so later eligible rows converge.
            pending_kwargs["unprojected_only"] = True
        for artifact in self.store.pending_tts(**pending_kwargs):
            artifact_turn_id = artifact.get("turn_id")
            if not isinstance(artifact_turn_id, str):
                continue
            if turn_id is not None and artifact_turn_id != turn_id:
                continue
            turn = self.store.get_turn(artifact_turn_id)
            jobs.append(
                self._enqueue_stage_job(
                    "tts",
                    {"turn_id": artifact_turn_id, "artifact_id": artifact["artifact_id"]},
                    idempotency_key=f"artifact:{artifact['artifact_id']}:tts",
                    provider_chain=self._chain_for_turn("tts", turn),
                    now=now,
                    worker_claim=worker_claim,
                )
            )
        return jobs

    def _enqueue_tts_jobs(
        self,
        turn_id: str,
        *,
        now: str | None = None,
        worker_claim: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        return self._enqueue_pending_tts_jobs(turn_id=turn_id, now=now, worker_claim=worker_claim)

    def accept_turn(
        self,
        turn_id: str,
        *,
        now: str | None = None,
        user_id: str | None = None,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        # Build the immutable provider snapshot before entering the acceptance
        # transaction.  RecorderStore persists it together with ACCEPTED and
        # the first worker intent; it must never be reconstructed after a
        # successful acceptance.
        current = self.store.get_turn(turn_id, user_id=user_id, device_id=device_id)
        audio = any(part.get("kind") == "audio" for part in current.get("parts", []))
        initial_chain = self._chain_for_turn("asr", current) if audio else None
        accepted = self.store.accept_turn(
            turn_id,
            now=now,
            user_id=user_id,
            device_id=device_id,
            enqueue_worker_job=True,
            provider_chain=initial_chain,
            max_attempts=3,
            deadline_seconds=(
                max(1, int(math.ceil(initial_chain.overall_deadline_seconds)))
                if initial_chain is not None else 300
            ),
        )
        return accepted

    def _default_worker_handlers(self) -> dict[str, Any]:
        def receipt(stage: str, identifier: str, *, status: str = "accepted", **extra: Any) -> dict[str, Any]:
            value: dict[str, Any] = {"effect_id": f"recorder:{stage}:{identifier}", "status": status}
            for key, item in extra.items():
                if isinstance(item, (str, int, float, bool)) or item is None:
                    value[key] = item
            return value

        def asr(job: Mapping[str, Any]) -> Mapping[str, Any]:
            turn_id = str(job["payload"]["turn_id"])
            try:
                result = self.run_asr(turn_id, frozen=job.get("provider_chain"), worker_claim=job)
            except ProviderFailure as exc:
                if not exc.retryable or int(job.get("attempt_count", 0)) < int(job.get("max_attempts", 0)):
                    raise
                self.store.commit_protocol_error(turn_id, "asr", message=FINAL_ERROR_MESSAGES["asr"], worker_claim=job)
                result = self.store.get_turn(turn_id)
            return receipt("asr", turn_id, outcome=result.get("authoritative_asr_outcome") or "pending")

        def route(job: Mapping[str, Any]) -> Mapping[str, Any]:
            result = self.route_next(
                str(job["payload"]["user_id"]),
                owner=str(job.get("_worker_owner") or f"worker:{job['job_id']}"),
                expected_turn_id=str(job["payload"]["turn_id"]),
                worker_claim=job,
            )
            if result is None:
                raise ProviderFailure("provider_unavailable", retryable=True)
            return receipt("route", str(job["payload"]["turn_id"]), state=result.get("state", "accepted"))

        def hermes(job: Mapping[str, Any]) -> Mapping[str, Any]:
            payload = job["payload"]
            turn_id = str(payload["turn_id"])
            submission_id = payload.get("hermes_submission_id")
            if not isinstance(submission_id, str) or not submission_id:
                ingress = self.store.get_ingress_for_turn(turn_id)
                if ingress is None:
                    raise ValidationError("Hermes worker submission is missing")
                submission_id = str(ingress["hermes_submission_id"])
            try:
                result = self.process_next_hermes(
                    str(payload["session_id"]),
                    owner=str(job.get("_worker_owner") or f"worker:{job['job_id']}"),
                    hermes_submission_id=submission_id,
                    expected_turn_id=turn_id,
                    now=job.get("_worker_now"),
                    worker_claim=job,
                )
            except ValidationError:
                raise ProviderFailure("provider_unavailable", retryable=False) from None
            if result is None:
                raise ProviderFailure("provider_unavailable", retryable=True)
            if result.get("state") in {"ROUTED", "HERMES_PENDING"} and not result.get("final_event_version"):
                raise ProviderFailure("transport", retryable=True)
            return receipt("hermes", str(payload["turn_id"]), state=result.get("state", "accepted"))

        def hermes_history(job: Mapping[str, Any]) -> Mapping[str, Any]:
            payload = job["payload"]
            submission_id = str(payload["hermes_submission_id"])
            ingress = self.store.get_ingress(submission_id)
            turn = self.store.get_turn(str(payload["turn_id"]))
            self._assert_worker_effect(job, stage="hermes", turn_id=str(payload["turn_id"]))
            if turn.get("final_outcome") == "success" or turn.get("state") not in {"LATE_RESULT_GRACE", "ROUTED", "HERMES_PENDING"}:
                return receipt("hermes-history", submission_id, status="already_terminal", state=turn.get("state"))
            if self.hermes is None:
                raise ProviderFailure("provider_unavailable", retryable=True)
            context = self.store.submission_context(submission_id)
            result = self._valid_terminal_hermes_result(
                self.hermes.history(session_key=ingress["gateway_session_key"], marker=ingress["marker"]),
                expected={
                    "submission_id": ingress["hermes_submission_id"],
                    "turn_id": ingress["turn_id"],
                    "marker": ingress["marker"],
                    "session_key": ingress["gateway_session_key"],
                    "run_id": context.run_id or ingress.get("run_id") or ingress.get("hermes_run_id"),
                    "request_sha256": context.canonical_request_sha256,
                    "subject_kind": "turn",
                },
            )
            if result is None:
                raise ProviderFailure("transport", retryable=True)
            combined_content = self._requery_combined_content(ingress, result)
            committed = self.store.commit_hermes_result(
                submission_id,
                result,
                combined_content=combined_content,
                now=None,
                worker_claim=job,
            )
            return receipt("hermes-history", submission_id, state=committed.get("state", "accepted"))

        def eavesdrop(job: Mapping[str, Any]) -> Mapping[str, Any]:
            result = self.process_eavesdrop_segment(
                str(job["payload"]["session_id"]),
                int(job["payload"]["segment_sequence"]),
                owner=str(job.get("_worker_owner") or f"worker:{job['job_id']}"),
                now=job.get("_worker_now"),
                expected_segment_sha256=job["payload"].get("segment_sha256"),
                worker_claim=job,
            )
            if result is None:
                raise ProviderFailure("provider_unavailable", retryable=True)
            return receipt("eavesdrop", f"{job['payload']['session_id']}:{job['payload']['segment_sequence']}", state=result.get("state", "accepted"))

        def tts(job: Mapping[str, Any]) -> Mapping[str, Any]:
            result = self.generate_tts(str(job["payload"]["artifact_id"]), frozen=job.get("provider_chain"), worker_claim=job)
            if result.get("status") == "FAILED_GENERATION":
                error_kind = "provider_unavailable"
                status_code = None
                raw_metadata = result.get("provider_metadata_json")
                if isinstance(raw_metadata, str):
                    try:
                        parsed_metadata = json.loads(raw_metadata)
                        if isinstance(parsed_metadata, Mapping) and isinstance(parsed_metadata.get("error_kind"), str):
                            error_kind = parsed_metadata["error_kind"]
                        if isinstance(parsed_metadata, Mapping):
                            candidate_status = parsed_metadata.get("status_code")
                            if isinstance(candidate_status, int) and not isinstance(candidate_status, bool) and 100 <= candidate_status <= 599:
                                status_code = candidate_status
                    except json.JSONDecodeError:
                        pass
                retryable = error_kind in {"transport", "dns", "connect", "timeout", "rate_limited", "server", "provider_unavailable", "capacity"}
                raise ProviderFailure(error_kind, retryable=retryable, status_code=status_code)
            return receipt("tts", str(job["payload"]["artifact_id"]), state=result.get("status", "accepted"))

        def scheduler(job: Mapping[str, Any]) -> Mapping[str, Any]:
            result = self.run_scheduler(
                owner=str(job.get("_worker_owner") or f"worker:{job['job_id']}"),
                now=job.get("payload", {}).get("now"),
            )
            return receipt("scheduler", job["job_id"], count=len(result))

        return {"asr": asr, "route": route, "hermes": hermes, "hermes_history": hermes_history, "eavesdrop": eavesdrop, "tts": tts, "scheduler": scheduler}

    def run_background_worker_once(self, *, owner: str = "recorder-worker-1", now: str | None = None, lease_seconds: int = 30) -> dict[str, Any] | None:
        # Process already durable work first.  Reconciliation is deliberately
        # an idle-tick action: an enqueue fault must be represented by the
        # scheduler/worker job being processed rather than escaping before its
        # lease and retry receipt are updated.
        self.store.expire_tts_artifacts(now=now)
        receipt = self.run_durable_worker_once(
            owner=owner,
            handlers=self._default_worker_handlers(),
            now=now,
            lease_seconds=lease_seconds,
        )
        if receipt is not None:
            return receipt
        timestamp = now or self.store._now()
        # A deadline sweep may have terminalized a job without claiming any
        # handler.  Do not immediately select unrelated client TTS backlog in
        # that same tick; the next tick is the recovery boundary and avoids
        # reporting new work for a request that just converged to EXPIRED.
        if any(
            job.get("status") == "FAILED_PERMANENT"
            and job.get("last_error_kind") == "deadline"
            and job.get("updated_at") == timestamp
            for job in self.store.list_worker_jobs()
        ):
            return None
        try:
            self._enqueue_pending_tts_jobs(now=now, scheduled_only=False)
        except sqlite3.DatabaseError as exc:
            raise ProviderFailure("transport", retryable=True) from exc
        return self.run_durable_worker_once(
            owner=owner,
            handlers=self._default_worker_handlers(),
            now=now,
            lease_seconds=lease_seconds,
        )

    def accept_text_turn(
        self,
        manifest: Mapping[str, Any],
        text: str,
        *,
        require_registered_device: bool = False,
    ) -> dict[str, Any]:
        manifest = dict(manifest)
        if manifest.get("parts"):
            raise ValidationError("accept_text_turn expects a manifest without parts")
        if not isinstance(text, str):
            raise ValidationError("text must be a JSON string")
        payload = text.encode("utf-8")
        manifest.pop("text", None)
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
        self.store.create_turn(manifest, require_registered_device=require_registered_device)
        owner = {
            "user_id": manifest.get("user_id") if require_registered_device else None,
            "device_id": manifest.get("origin_device_id") if require_registered_device else None,
        }
        self.store.put_chunk(manifest["turn_id"], "text-1", 0, payload, **owner)
        self.store.finish_part(
            manifest["turn_id"],
            "text-1",
            total_chunks=1,
            total_bytes=len(payload),
            whole_stream_sha256=hashlib.sha256(payload).hexdigest(),
            **owner,
        )
        return self.accept_turn(manifest["turn_id"], **owner)

    # ---- Small HTTP surface ----------------------------------------------

    def handle_http(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes,
        *,
        peer_addr: tuple[str, int] | None = None,
        _admitted: bool = False,
    ) -> tuple[int, dict[str, str], Any]:
        admitted = _admitted
        try:
            if not admitted:
                self._begin_operation()
                admitted = True
            result = self._handle_http(method, target, headers, body, peer_addr=peer_addr)
            path = urlsplit(target).path.rstrip("/") or "/"
            response_status, response_headers, response_payload = result
            if method.upper() == "HEAD":
                response_headers = dict(response_headers)
                if isinstance(response_payload, ManagedFileBody):
                    response_payload.close()
                    encoded = b""
                    body_length = response_headers.get("Content-Length", "0")
                else:
                    encoded = response_payload if isinstance(response_payload, bytes) else json.dumps(
                        response_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    body_length = str(len(encoded))
                if not any(key.lower() == "content-type" for key in response_headers):
                    response_headers["Content-Type"] = (
                        "application/octet-stream" if isinstance(response_payload, (bytes, ManagedFileBody)) else "application/json; charset=utf-8"
                    )
                if not any(key.lower() == "content-length" for key in response_headers):
                    response_headers["Content-Length"] = body_length
                response_payload = b""
                result = response_status, response_headers, response_payload
            operation = match_operation(path, method)
            projected_payload = project_response(operation, result[0], result[2])
            result = result[0], result[1], projected_payload
            validate_response(operation, result[0], result[1], result[2])
            return result
        except RecorderError as exc:
            payload = {"error": {"code": exc.code, "message": exc.message}}
            if method.upper() == "HEAD":
                encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                return exc.status, {"Content-Type": "application/json", "Content-Length": str(len(encoded))}, b""
            return exc.status, {"Content-Type": "application/json"}, payload
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            del exc
            return 400, {"Content-Type": "application/json"}, {"error": {"code": "INVALID_REQUEST", "message": "request is invalid"}}
        except Exception:
            return 500, {"Content-Type": "application/json"}, {"error": {"code": "INTERNAL_ERROR", "message": "request failed"}}
        finally:
            if admitted and not _admitted:
                self._end_operation()

    @staticmethod
    def _json_body(body: bytes, decoded: dict[str, Any] | None = None) -> dict[str, Any]:
        if decoded is not None:
            return decoded
        if not body:
            return {}
        value = strict_json_loads(body)
        if not isinstance(value, dict):
            raise ValidationError("JSON body must be an object")
        return value

    @staticmethod
    def _header_value(headers: Mapping[str, str], name: str) -> str | None:
        wanted = name.lower()
        values = [value for key, value in headers.items() if str(key).lower() == wanted]
        return values[0] if len(values) == 1 else None

    @staticmethod
    def _header_values(headers: Mapping[str, str], name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in headers.items() if str(key).lower() == wanted]

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

    @classmethod
    def _request_owner(cls, query: Mapping[str, str], headers: Mapping[str, str]) -> tuple[str, str]:
        query_user = query.get("user_id")
        query_device = query.get("device_id")
        header_user = cls._header_value(headers, "X-Recorder-User-ID") or cls._header_value(headers, "X-Recorder-Principal-User")
        header_device = cls._header_value(headers, "X-Recorder-Device-ID") or cls._header_value(headers, "X-Recorder-Principal-Device")
        if query_user is not None and header_user is not None and query_user != header_user:
            raise UnauthorizedError("request identity fields do not agree")
        if query_device is not None and header_device is not None and query_device != header_device:
            raise UnauthorizedError("request identity fields do not agree")
        user_id = query_user if query_user is not None else header_user
        device_id = query_device if query_device is not None else header_device
        if not isinstance(user_id, str) or not user_id or not isinstance(device_id, str) or not device_id:
            raise UnauthorizedError("a registered user and device are required")
        return user_id, device_id

    @classmethod
    def _payload_owner(cls, payload: Mapping[str, Any], *, device_key: str = "device_id") -> tuple[str, str]:
        user_id = cls._json_string(payload, "user_id")
        device_id = cls._json_string(payload, device_key)
        return user_id, device_id

    def _authenticated_owner(self, query: Mapping[str, str], headers: Mapping[str, str]) -> tuple[str, str]:
        user_id, device_id = self._request_owner(query, headers)
        self.store.assert_active_device(user_id, device_id)
        return user_id, device_id

    def _verify_principal_headers(
        self,
        query: Mapping[str, str],
        headers: Mapping[str, str],
    ) -> tuple[str, str]:
        if self._ingress_secret is None:
            raise UnauthorizedError("authenticated ingress is not configured")
        principal_names = (
            "X-Recorder-Principal-User",
            "X-Recorder-Principal-Device",
            "X-Recorder-Principal-Signature",
        )
        if any(len(self._header_values(headers, name)) > 1 for name in principal_names):
            raise ValidationError("duplicate principal headers are not permitted")
        principal_user = self._header_value(headers, "X-Recorder-Principal-User")
        principal_device = self._header_value(headers, "X-Recorder-Principal-Device")
        proof = self._header_value(headers, "X-Recorder-Principal-Signature")
        if not principal_user or not principal_device or proof is None:
            raise UnauthorizedError("verified request principal is required")
        if any(not isinstance(value, str) or not value or "\x00" in value for value in (principal_user, principal_device)):
            raise UnauthorizedError("verified request principal is invalid")
        message = f"{principal_user}\x00{principal_device}".encode("utf-8")
        expected = hmac.new(self._ingress_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(proof, expected):
            raise UnauthorizedError("verified request principal is invalid")
        # HMAC verifies the asserted tuple; the device row is the second
        # authority boundary.  In particular this prevents a revoked identity
        # from reaching the registration/worker handlers.
        self.store.assert_active_device(principal_user, principal_device)
        for name in ("X-Recorder-User-ID", "X-Recorder-Device-ID"):
            if len(self._header_values(headers, name)) > 1:
                raise ValidationError(f"duplicate {name} headers are not permitted")
        query_pairs = {key: query.get(key) for key in ("user_id", "device_id", "phone_device_id")}
        claimed_header_user = self._header_value(headers, "X-Recorder-User-ID")
        claimed_header_device = self._header_value(headers, "X-Recorder-Device-ID")
        if claimed_header_user is not None and claimed_header_user != principal_user:
            raise UnauthorizedError("request identity does not match verified principal")
        if claimed_header_device is not None and claimed_header_device != principal_device:
            raise UnauthorizedError("request identity does not match verified principal")
        for key, value in query_pairs.items():
            if value is None:
                continue
            expected_value = principal_user if key == "user_id" else principal_device
            if value != expected_value:
                raise UnauthorizedError("request identity does not match verified principal")
        return principal_user, principal_device

    def _verify_network_principal(
        self,
        query: Mapping[str, str],
        headers: Mapping[str, str],
        body: bytes,
        *,
        path: str,
        raw_chunk: bool = False,
        principal: tuple[str, str] | None = None,
    ) -> dict[str, Any] | None:
        principal = principal or self._verify_principal_headers(query, headers)
        principal_user, principal_device = principal
        content_type = self._header_value(headers, "Content-Type")
        media_type = content_type.split(";", 1)[0].strip().lower() if isinstance(content_type, str) else None
        if body and not raw_chunk and media_type != "application/json":
            raise UnsupportedMediaType("JSON routes require Content-Type: application/json")
        if body and raw_chunk and media_type != "application/octet-stream":
            raise UnsupportedMediaType("chunk routes require an octet-stream body")
        if body and not raw_chunk:
            try:
                decoded = strict_json_loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise ValidationError("request body is not valid JSON") from exc
            if not isinstance(decoded, dict):
                raise ValidationError("request body must be a JSON object")
            if "now" in decoded:
                raise ValidationError("server time cannot be supplied by a client")
            for key in ("user_id", "device_id", "origin_device_id", "phone_device_id", "actor_device_id"):
                value = decoded.get(key)
                if value is None:
                    continue
                if key == "origin_device_id" and path == "/v1/internal/schedule_create":
                    # A scheduler principal is an internal backend identity;
                    # the durable schedule origin is authorized against the
                    # parent turn in RecorderStore.
                    continue
                expected_value = principal_user if key == "user_id" else principal_device
                if value != expected_value:
                    raise UnauthorizedError("request identity does not match verified principal")
            return decoded
        return None

    def _assert_internal_principal(self, principal: tuple[str, str]) -> None:
        if not self._internal_worker_principals or principal not in self._internal_worker_principals:
            raise ForbiddenError("worker controls are not enabled for this principal")

    def _assert_worker_principal(self, principal: tuple[str, str]) -> None:
        """Compatibility name for callers that used the old worker gate."""
        self._assert_internal_principal(principal)

    def _prepare_http_request(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str],
        *,
        body_length: int,
        peer_addr: tuple[str, int] | None,
    ) -> tuple[str, dict[str, str], list[str], Any, tuple[str, str] | None]:
        requested_method = method.upper()
        parsed = urlsplit(target)
        path = parsed.path.rstrip("/") or "/"
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
        query_counts: dict[str, int] = {}
        for key, _value in query_pairs:
            query_counts[key] = query_counts.get(key, 0) + 1
        query = dict(query_pairs)
        segments = [unquote(item) for item in path.split("/") if item]
        operation = match_operation(path, requested_method)
        network = peer_addr is not None
        principal: tuple[str, str] | None = None
        if network and operation.requires_principal:
            principal = self._verify_principal_headers(query, headers)
            if operation.requires_internal:
                self._assert_internal_principal(principal)
        if any(count > 1 for count in query_counts.values()):
            raise ValidationError("duplicate query parameters are not permitted")
        validate_request_headers(
            operation,
            path=path,
            query=query,
            headers=headers,
            body_length=body_length,
            network=network,
        )
        return path, query, segments, operation, principal

    def preflight_http(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str],
        *,
        body_length: int,
        peer_addr: tuple[str, int],
    ) -> None:
        """Authenticate and validate an HTTP request without reading its body."""
        if self._shutdown_requested.is_set():
            raise ServiceStoppingError("Recorder service is draining and is not accepting new work")
        if body_length > self._wire_policy.gateway_max_request_bytes:
            raise GatewayRequestTooLargeError("request exceeds the configured Gateway limit")
        self._prepare_http_request(
            method,
            target,
            headers,
            body_length=body_length,
            peer_addr=peer_addr,
        )

    def _handle_http(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes,
        *,
        peer_addr: tuple[str, int] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        requested_method = method.upper()
        method = requested_method
        if method == "HEAD":
            method = "GET"
        path, query, segments, operation, principal = self._prepare_http_request(
            requested_method,
            target,
            headers,
            body_length=len(body),
            peer_addr=peer_addr,
        )
        decoded_payload: dict[str, Any] | None = None

        def json_body() -> dict[str, Any]:
            nonlocal decoded_payload
            if decoded_payload is None:
                decoded_payload = self._json_body(body)
            return decoded_payload

        if peer_addr is not None and operation.requires_principal:
            raw_chunk = len(segments) == 7 and segments[:2] == ["v1", "turns"] and segments[3] == "parts" and segments[5] == "chunks"
            decoded_payload = self._verify_network_principal(query, headers, body, path=path, raw_chunk=raw_chunk, principal=principal)
            if "now" in query:
                raise ValidationError("server time cannot be supplied by a client")
        decoded_payload = validate_request(
            operation,
            path=path,
            query=query,
            headers=headers,
            body=body,
            decoded=decoded_payload,
            network=peer_addr is not None,
        )
        if method == "GET" and path in {"/healthz", "/v1/health"}:
            if not self._voice_ready():
                raise VoiceNotReadyError()
            return 200, {}, {"status": "ok", "product_identity": "recorder-next-server-product-items-1-through-8", "api_version": "v1", "worker": self.store.worker_health()}
        if method == "GET" and path == "/v1/openapi.json":
            from .openapi import OPENAPI

            return 200, {}, OPENAPI
        if segments[:3] == ["v1", "internal", "worker"] and len(segments) == 4 and method == "POST":
            payload = json_body()
            action = segments[3]
            if action == "claim":
                WORKER_CLAIM.validate(payload)
                if set(payload) - {"owner", "lease_seconds"}:
                    raise ValidationError("worker claim contains unsupported fields")
                owner = self._json_string(payload, "owner") if "owner" in payload else "worker-1"
                lease_seconds = self._json_integer(payload, "lease_seconds") if "lease_seconds" in payload else 30
                assert lease_seconds is not None
                return 200, {}, {"job": self.store.claim_worker_job(owner, lease_seconds=lease_seconds)}
            if action == "recover":
                WORKER_RECOVER.validate(payload)
                if payload:
                    raise ValidationError("worker recover body must be empty")
                return 200, {}, self.store.recover_worker_jobs()
            if action == "complete":
                WORKER_COMPLETE.validate(payload)
                if set(payload) != {"job_id", "owner", "lease_token", "receipt"} or not isinstance(payload.get("receipt"), Mapping):
                    raise ValidationError("worker completion requires job_id, owner, lease_token, and receipt")
                return 200, {}, self.store.complete_worker_job(
                    self._json_string(payload, "job_id"),
                    self._json_string(payload, "owner"),
                    payload["receipt"],
                    lease_token=self._json_string(payload, "lease_token"),
                )
            if action == "fail":
                WORKER_FAIL.validate(payload)
                if set(payload) - {"job_id", "owner", "lease_token", "error_kind", "retryable", "status_code", "retry_after_seconds"}:
                    raise ValidationError("worker failure contains unsupported fields")
                error_kind = self._json_string(payload, "error_kind") if "error_kind" in payload else "internal"
                retryable = payload.get("retryable", False)
                if not isinstance(retryable, bool):
                    raise ValidationError("retryable must be boolean")
                status_code = self._json_integer(payload, "status_code", allow_none=True) if "status_code" in payload else None
                retry_after = self._json_integer(payload, "retry_after_seconds", allow_none=True) if "retry_after_seconds" in payload else None
                return 200, {}, self.store.fail_worker_job(
                    self._json_string(payload, "job_id"),
                    self._json_string(payload, "owner"),
                    error_kind=error_kind,
                    retryable=retryable,
                    lease_token=self._json_string(payload, "lease_token"),
                    status_code=status_code,
                    retry_after_seconds=retry_after,
                )
            if action == "run":
                WORKER_RUN.validate(payload)
                if set(payload) - {"owner", "lease_seconds"}:
                    raise ValidationError("worker run contains unsupported fields")
                owner = self._json_string(payload, "owner") if "owner" in payload else "worker-1"
                lease_seconds = self._json_integer(payload, "lease_seconds") if "lease_seconds" in payload else 30
                assert lease_seconds is not None
                return 200, {}, {"job": self.run_background_worker_once(owner=owner, lease_seconds=lease_seconds)}
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
        if segments[:4] == ["v1", "internal", "worker", "health"] and method == "GET":
            return 200, {}, self.store.worker_health(now=query.get("now"))
        if segments[:2] == ["v1", "history"] and len(segments) == 2 and method == "GET":
            user_id, _device_id = self._authenticated_owner(query, headers)
            since_seq = self._query_integer(query, "since_seq", minimum=0)
            return 200, {}, self.store.history_read_model(
                user_id,
                project_id=query.get("project_id"),
                include_archived=query.get("include_archived") == "true",
                input_type=query.get("input_type"),
                cursor=query.get("cursor"),
                since_seq=since_seq,
                limit=self._query_integer(query, "limit", default=50, minimum=1, maximum=200) or 50,
            )
        if segments[:2] == ["v1", "eavesdrop"] and len(segments) == 2 and method == "POST":
            payload = json_body()
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
                payload = json_body()
                args = (session_id, self._json_string(payload, "user_id"), self._json_string(payload, "phone_device_id"))
                action = segments[3]
                result = {"activate": self.store.activate_eavesdrop, "pause": self.store.pause_eavesdrop, "resume": self.store.resume_eavesdrop, "stop": self.store.stop_eavesdrop}[action](*args, now=payload.get("now"))
                return 200, {}, result
            if len(segments) == 4 and segments[3] == "segments" and method == "POST":
                payload = json_body()
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
                payload = json_body()
                return 200, {}, self.store.route_eavesdrop_segment(session_id, self._json_string(payload, "user_id"), self._json_string(payload, "phone_device_id"), segment_sequence=self._json_integer(payload, "segment_sequence"), now=payload.get("now"))
            if len(segments) == 6 and segments[3] == "segments" and segments[5] == "route" and method == "POST":
                payload = json_body()
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
            payload = json_body()
            event_id = self._json_string(payload, "event_id") if "event_id" in payload and payload["event_id"] is not None else None
            expires_at = self._json_string(payload, "expires_at") if "expires_at" in payload and payload["expires_at"] is not None else None
            enabled = payload.get("enabled", True)
            if not isinstance(enabled, bool):
                raise ValidationError("enabled must be boolean")
            return 201, {}, self.store.record_diagnostics_opt_in(self._json_string(payload, "user_id"), self._json_string(payload, "device_id"), event_id=event_id, enabled=enabled, expires_at=expires_at, now=payload.get("now"))
        if segments[:3] == ["v1", "diagnostics", "events"] and method == "POST":
            payload = json_body()
            occurred_at = self._json_string(payload, "occurred_at") if "occurred_at" in payload and payload["occurred_at"] is not None else None
            return 201, {}, self.store.ingest_diagnostic_event(self._json_string(payload, "user_id"), self._json_string(payload, "device_id"), event_id=self._json_string(payload, "event_id"), idempotency_key=self._json_string(payload, "idempotency_key"), payload=payload.get("payload", {}), occurred_at=occurred_at, now=payload.get("now"))
        if segments[:3] == ["v1", "diagnostics", "bundles"] and method == "POST":
            payload = json_body()
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
            user_id, device_id = self._authenticated_owner(query, headers)
            return 200, {}, self.store.list_diagnostics(user_id, device_id, category=query.get("category"), stage=query.get("stage"), limit=self._query_integer(query, "limit", default=100, minimum=1, maximum=500) or 100)
        if segments[:3] == ["v1", "diagnostics", "export"] and method == "GET":
            user_id, device_id = self._authenticated_owner(query, headers)
            return 200, {}, self.store.export_diagnostics(
                user_id,
                device_id,
                category=query.get("category"),
                stage=query.get("stage"),
                cursor=query.get("cursor"),
                limit=self._query_integer(query, "limit", default=100, minimum=1, maximum=500) or 100,
                max_bytes=self._query_integer(query, "max_bytes", default=None, minimum=1024, maximum=64 * 1024 * 1024),
            )
        if segments[:3] == ["v1", "diagnostics", "delete"] and method == "POST":
            payload = json_body()
            user_id, device_id = self._payload_owner(payload)
            return 200, {}, self.store.delete_diagnostics(user_id, device_id, now=payload.get("now"))
        if segments[:2] == ["v1", "diagnostics"] and len(segments) == 2 and method == "DELETE":
            payload = json_body() if body else {}
            if "user_id" in query or "device_id" in query:
                user_id, device_id = self._authenticated_owner(query, headers)
            else:
                user_id, device_id = self._payload_owner(payload)
                self.store.assert_active_device(user_id, device_id)
            return 200, {}, self.store.delete_diagnostics(user_id, device_id, now=query.get("now") or payload.get("now"))
        if segments[:3] == ["v1", "internal", "schedule_create"] and method == "POST":
            return 201, {}, self.schedule_create(
                json_body(),
                principal=principal if peer_addr is not None else None,
            )
        if segments[:3] == ["v1", "internal", "scheduler"] and len(segments) == 4 and segments[3] == "fire" and method == "POST":
            payload = json_body()
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
            payload = json_body()
            return 200, {}, self.recover_scheduler(now=payload.get("now"))
        if segments[:2] == ["v1", "schedules"] and len(segments) == 3 and method == "GET":
            user_id, device_id = self._authenticated_owner(query, headers)
            return 200, {}, self.store.get_schedule(segments[2], user_id=user_id, device_id=device_id)
        if segments[:3] == ["v1", "devices", "register"] and len(segments) == 3 and method == "POST":
            payload = json_body()
            return 201, {}, self.store.confirm_device(
                self._json_string(payload, "user_id"),
                self._json_string(payload, "device_id"),
                self._json_string(payload, "kind"),
            )
        if segments[:2] == ["v1", "devices"] and len(segments) == 2 and method == "POST":
            payload = json_body()
            if peer_addr is None:
                return 201, {}, self.store.register_device(self._json_string(payload, "user_id"), self._json_string(payload, "device_id"), self._json_string(payload, "kind"))
            return 201, {}, self.store.confirm_device(self._json_string(payload, "user_id"), self._json_string(payload, "device_id"), self._json_string(payload, "kind"))
        if segments[:2] == ["v1", "devices"] and len(segments) == 4 and segments[3] == "revoke" and method == "POST":
            payload = json_body()
            user_id = self._json_string(payload, "user_id")
            actor_device_id = self._json_string(payload, "actor_device_id")
            self.store.revoke_device(user_id, segments[2], actor_device_id=actor_device_id)
            return 200, {}, self.store.get_device(user_id, segments[2])
        if segments[:2] == ["v1", "turns"] and len(segments) == 2 and method == "POST":
            payload = json_body()
            if "text" in payload and not payload.get("parts"):
                if not isinstance(payload["text"], str):
                    raise ValidationError("text must be a JSON string")
                manifest = {key: value for key, value in payload.items() if key != "text"}
                self._payload_owner(manifest, device_key="origin_device_id")
                return 202, {}, self.accept_text_turn(manifest, payload["text"], require_registered_device=True)
            self._payload_owner(payload, device_key="origin_device_id")
            return 201, {}, self.store.create_turn(payload, require_registered_device=True)
        if segments[:2] == ["v1", "turns"] and len(segments) == 4 and segments[3] == "accept" and method == "POST":
            payload = json_body()
            user_id, device_id = self._payload_owner(payload)
            return 200, {}, self.accept_turn(segments[2], user_id=user_id, device_id=device_id)
        if segments[:2] == ["v1", "turns"] and len(segments) == 3:
            turn_id = segments[2]
            if method == "GET":
                user_id, device_id = self._authenticated_owner(query, headers)
                return 200, {}, self.store.get_turn(turn_id, user_id=user_id, device_id=device_id)
        if len(segments) >= 5 and segments[:2] == ["v1", "turns"] and segments[3] == "parts":
            turn_id, part_id = segments[2], segments[4]
            if len(segments) == 6 and segments[5] == "missing" and method == "GET":
                user_id, device_id = self._authenticated_owner(query, headers)
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
                    user_id=user_id,
                    device_id=device_id,
                )
                return 200, {}, {"turn_id": turn_id, "part_id": part_id, **page}
            if len(segments) == 7 and segments[5] == "chunks" and method in {"PUT", "POST"}:
                user_id, device_id = self._authenticated_owner(query, headers)
                if not segments[6].isdigit():
                    raise ValidationError("chunk sequence must be a non-negative integer")
                sequence = int(segments[6])
                result = self.store.put_chunk(
                    turn_id,
                    part_id,
                    sequence,
                    body,
                    expected_sha256=self._header_value(headers, "X-Chunk-SHA256"),
                    user_id=user_id,
                    device_id=device_id,
                )
                return 200, {}, result
            if len(segments) == 6 and segments[5] == "finish" and method == "POST":
                user_id, device_id = self._authenticated_owner(query, headers)
                payload = json_body()
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
                    user_id=user_id,
                    device_id=device_id,
                )
        if len(segments) in {5, 6} and segments[:2] == ["v1", "turns"] and segments[3] == "events" and (len(segments) == 5 or segments[5] == "ack") and method == "POST":
            payload = json_body()
            user_id, device_id = self._payload_owner(payload)
            event_version = self._json_integer(payload, "event_version")
            assert event_version is not None
            return 200, {}, self.store.ack_event(segments[2], segments[4], user_id=user_id, device_id=device_id, event_version=event_version, payload_sha256=self._json_string(payload, "payload_sha256"))
        if segments[:2] == ["v1", "outbox"] and method == "GET":
            user_id, device_id = self._authenticated_owner(query, headers)
            return 200, {}, {"items": self.store.pending_outbox(device_id, user_id=user_id, limit=self._query_integer(query, "limit", default=50, minimum=1, maximum=500) or 50)}
        if len(segments) == 4 and segments[:2] == ["v1", "tts"] and segments[3] == "bridge-read" and method == "GET":
            user_id, bridge_device_id = self._authenticated_owner(query, headers)
            metadata, audio = self.store.read_tts_for_bridge(segments[2], user_id=user_id, bridge_device_id=bridge_device_id)
            metadata["audio_base64"] = base64.b64encode(audio).decode("ascii")
            return 200, {}, metadata
        if segments[:2] == ["v1", "tts"] and len(segments) == 3 and method == "GET":
            user_id, device_id = self._authenticated_owner(query, headers)
            metadata, audio = self.store.read_tts(segments[2], user_id=user_id, device_id=device_id)
            metadata["audio_base64"] = base64.b64encode(audio).decode("ascii")
            return 200, {}, metadata
        if len(segments) == 4 and segments[:2] == ["v1", "tts"] and segments[3] == "playback-ack" and method == "POST":
            payload = json_body()
            user_id, device_id = self._payload_owner(payload)
            return 200, {}, self.store.ack_playback(
                segments[2],
                user_id=user_id,
                device_id=device_id,
                payload_sha256=self._json_string(payload, "payload_sha256"),
                turn_id=self._json_string(payload, "turn_id"),
                artifact_version=self._json_integer(payload, "artifact_version"),
            )
        if len(segments) == 4 and segments[:2] == ["v1", "tts"] and segments[3] == "relay-received" and method == "POST":
            payload = json_body()
            user_id, device_id = self._payload_owner(payload)
            return 200, {}, self.store.relay_tts_received(segments[2], user_id=user_id, device_id=device_id, payload_sha256=self._json_string(payload, "payload_sha256"))
        if segments[:2] == ["v1", "projects"] and len(segments) == 2:
            if method == "GET":
                user_id, _device_id = self._authenticated_owner(query, headers)
                return 200, {}, {"items": self.store.list_projects(user_id, include_archived=query.get("include_archived") == "true")}
            if method == "POST":
                payload = json_body()
                user_id, device_id = self._payload_owner(payload)
                self.store.assert_active_device(user_id, device_id)
                optional_string = lambda key: self._json_string(payload, key) if key in payload and payload[key] is not None else None
                project_kwargs: dict[str, Any] = {
                    "project_number": self._json_string(payload, "project_number"),
                    "name": self._json_string(payload, "name"),
                    "description": payload.get("description", ""),
                    "idempotency_key": optional_string("idempotency_key"),
                }
                if "aliases" in payload:
                    project_kwargs["aliases"] = payload["aliases"]
                return 201, {}, self.store.create_project(user_id, **project_kwargs)
        if segments[:3] == ["v1", "projects", "search"] and method == "GET":
            user_id, _device_id = self._authenticated_owner(query, headers)
            return 200, {}, {"items": self.store.search_projects(user_id, query.get("q", ""), include_archived=query.get("include_archived") == "true")}
        if segments[:2] == ["v1", "projects"] and len(segments) >= 3:
            project_id = segments[2]
            if len(segments) == 3 and method == "GET":
                user_id, _device_id = self._authenticated_owner(query, headers)
                return 200, {}, self.store.get_project(user_id, project_id, include_archived=True)
            if len(segments) == 3 and method == "PATCH":
                user_id, _device_id = self._authenticated_owner(query, headers)
                payload = json_body()
                expected_version = self._json_integer(payload, "expected_version")
                assert expected_version is not None
                patch = dict(payload)
                patch.pop("expected_version", None)
                return 200, {}, self.store.update_project(user_id, project_id, expected_version=expected_version, patch=patch)
            if len(segments) == 4 and segments[3] == "archive" and method == "POST":
                user_id, _device_id = self._authenticated_owner(query, headers)
                payload = json_body()
                expected_version = self._json_integer(payload, "expected_version")
                assert expected_version is not None
                return 200, {}, self.store.archive_project(user_id, project_id, expected_version=expected_version)
        if segments[:2] == ["v1", "turns"] and len(segments) == 4 and segments[3] == "archive" and method == "POST":
            user_id, device_id = self._authenticated_owner(query, headers)
            payload = json_body()
            source = payload.get("source", "api")
            if not isinstance(source, str) or not source:
                raise ValidationError("source must be a non-empty string")
            return 200, {}, self.store.archive_turn(user_id, segments[2], source=source, device_id=device_id)
        raise NotFoundError("API route not found")


def create_service(db_path: str, storage_root: str, *, clock: Any | None = None, **kwargs: Any) -> RecorderService:
    kwargs.setdefault("asr_fallback_order", ())
    return RecorderService(RecorderStore(db_path, storage_root=storage_root, clock=clock), **kwargs)


def create_configured_service(
    config: "RecorderConfig",
    *,
    ingress_secret: str | None = None,
    require_production: bool = False,
) -> RecorderService:
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
            endpoint = endpoint or config.hermes_audio_base_url
            credential_file = credential_file or config.hermes_api_key_file
            if not endpoint or not credential_file:
                raise CredentialError("configured Hermes audio provider requires hermes_audio_base_url and credential file")
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
            if declaration.adapter in {"hermes", "hermes-default"}:
                if declaration.endpoint is None and kind in {"asr", "tts"} and config.hermes_audio_base_url:
                    declared["endpoint"] = config.hermes_audio_base_url
                effective_profile = declaration.profile if declaration.profile != "default" else config.hermes_profile
                declared["profile"] = effective_profile
            effective_credential_file = declaration.credential_file
            if effective_credential_file is None and declaration.adapter in {"hermes", "hermes-default"}:
                effective_credential_file = config.hermes_api_key_file
            if effective_credential_file:
                # Bind the non-secret reference, never credential contents.
                declared["credential_configured"] = True
                declared["credential_ref_sha256"] = hashlib.sha256(str(effective_credential_file).encode("utf-8")).hexdigest()
            targets.append(ProviderTarget(name, kind, declaration.adapter, provider, retries=declaration.retries, timeout_seconds=declaration.timeout_seconds, declared=declared))
        return ProviderChain(kind, targets, overall_deadline_seconds=deadline)

    asr_declarations = tuple(getattr(config, "asr_providers", ()))
    tts_declarations = tuple(getattr(config, "tts_providers", ()))
    asr_global_names = tuple(getattr(config, "asr_chain", ()))
    tts_global_names = tuple(getattr(config, "tts_chain", ()))
    if not asr_declarations and not asr_global_names and config.asr_source == "hermes" and config.hermes_audio_base_url and config.hermes_api_key_file:
        asr_declarations = (
            ProviderConfig.from_spec(
                "hermes-default",
                "asr",
                {"adapter": "hermes", "endpoint": config.hermes_audio_base_url, "profile": config.hermes_profile, "credential_file": config.hermes_api_key_file, "enabled": True},
            ),
        )
        asr_global_names = ("hermes-default",)
    if not tts_declarations and not tts_global_names and config.tts_source == "hermes" and config.hermes_audio_base_url and config.hermes_api_key_file:
        tts_declarations = (
            ProviderConfig.from_spec(
                "hermes-default",
                "tts",
                {"adapter": "hermes", "endpoint": config.hermes_audio_base_url, "profile": config.hermes_profile, "credential_file": config.hermes_api_key_file, "enabled": True},
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

    production_readiness: dict[str, bool] | None = None
    if require_production:
        effective_ingress_secret = ingress_secret if ingress_secret is not None else os.environ.get("RECORDER_INGRESS_SECRET")
        if not isinstance(effective_ingress_secret, str) or not effective_ingress_secret:
            raise CredentialError("production Recorder ingress secret is required")
        if configured_asr_chain is None or configured_tts_chain is None:
            raise CredentialError("production Recorder requires configured ASR and TTS chains")
        if not config.hermes_base_url or not config.hermes_api_key_file:
            raise CredentialError("production Recorder requires an authenticated Hermes gateway")

        def probe_chain(chain: ProviderChain, kind: str) -> None:
            for target in chain.targets:
                if target.source in {"fixture", "static", "test"}:
                    raise CredentialError(f"production {kind.upper()} chain contains a fixture provider")
                provider = target.provider
                readiness_check = getattr(provider, "readiness_check", None)
                if callable(readiness_check):
                    readiness_check()
                    continue
                health_check = getattr(provider, "health_check", None)
                capability_check = getattr(provider, "capability_check", None)
                if not callable(health_check) or not callable(capability_check):
                    raise CredentialError(f"production {kind.upper()} provider has no bounded capability probes")
                for result in (health_check(), capability_check()):
                    if not isinstance(result, Mapping) or result.get("configured") is False or result.get("ok") is False or result.get("ready") is False:
                        raise CredentialError(f"production {kind.upper()} provider capability is unavailable")

        probe_chain(configured_asr_chain, "asr")
        probe_chain(configured_tts_chain, "tts")
        HttpHermesGateway(
            config.hermes_base_url,
            api_key_file=config.hermes_api_key_file,
            max_request_bytes=config.gateway_max_request_bytes,
            require_existing_session=True,
        ).capability_check()
        production_readiness = {"asr": True, "tts": True, "hermes": True}

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
            endpoint = endpoint or config.hermes_audio_base_url
            if not endpoint:
                return None
            if not config.hermes_api_key_file:
                raise CredentialError("Hermes ASR requires hermes_audio_base_url and credential file")
            return HermesAudioASRProvider(
                endpoint,
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
        endpoint = config.hermes_audio_base_url
        if not endpoint:
            tts = DisabledTTSProvider()
        else:
            if not config.hermes_api_key_file:
                raise CredentialError("Hermes TTS requires hermes_audio_base_url and credential file")
            tts = HermesAudioTTSProvider(
                endpoint,
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
        hermes = HttpHermesGateway(
            config.hermes_base_url,
            api_key_file=config.hermes_api_key_file,
            max_request_bytes=config.gateway_max_request_bytes,
            require_existing_session=require_production,
        )

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
        diagnostics_tombstone_retention_seconds=config.diagnostics_tombstone_retention_seconds,
        diagnostics_export_max_bytes=config.diagnostics_export_max_bytes,
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
        ingress_secret=ingress_secret,
        internal_worker_principals=config.internal_worker_principals,
        gateway_max_request_bytes=config.gateway_max_request_bytes,
        production_readiness=production_readiness,
    )
