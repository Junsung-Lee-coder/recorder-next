import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recorder_next.adapters import HermesResult, HttpHermesGateway
from recorder_next.config import RecorderConfig
from recorder_next.hermes_wire import SubmissionContext
from recorder_next.service import RecorderService
from recorder_next.store import RecorderStore


TARGET_SESSION_ID = "20260703_210417_8f66b434"
CONVERSATION_KEY = "agent:main:discord:thread:approved-creator"
SUBMISSION_ID = "e11-submission-1"


def _context(*, session_id: str = TARGET_SESSION_ID) -> SubmissionContext:
    return SubmissionContext(
        submission_id=SUBMISSION_ID,
        subject_kind="turn",
        marker="marker-e11",
        gateway_session_key=session_id,
        canonical_request_sha256="a" * 64,
        wire_revision="recorder-hermes-v1",
        request={"input": "E11 durable request"},
        turn_id="018f5a2e-7b6e-7abc-8d11-1234567890e1",
    )


class _DurableRunGateway(HttpHermesGateway):
    def __init__(self, *, returned_session_id: str = TARGET_SESSION_ID) -> None:
        super().__init__(
            "http://127.0.0.1:9",
            gateway_session_key=CONVERSATION_KEY,
            require_existing_session=True,
            poll_interval_seconds=0,
            run_timeout_seconds=2,
            max_submit_attempts=2,
        )
        self.returned_session_id = returned_session_id
        self.calls: list[tuple[str, str, dict | None, dict[str, str]]] = []
        self.created_run_ids: dict[str, str] = {}
        self.effect_count = 0
        self.lose_first_post_response = False
        self._response_lost = False

    def _request(
        self,
        method,
        path,
        payload=None,
        *,
        extra_headers=None,
        timeout_seconds=None,
        deadline_at=None,
    ):
        del timeout_seconds, deadline_at
        headers = dict(extra_headers or {})
        body = dict(payload) if payload is not None else None
        self.calls.append((method, path, body, headers))
        if method == "GET" and path == f"/api/sessions/{TARGET_SESSION_ID}":
            return {
                "object": "hermes.session",
                "session": {"id": TARGET_SESSION_ID, "archived": False, "ended_at": None},
            }
        if method == "POST" and path == "/v1/runs":
            idempotency_key = headers["Idempotency-Key"]
            run_id = self.created_run_ids.get(idempotency_key)
            if run_id is None:
                run_id = "run-e11"
                self.created_run_ids[idempotency_key] = run_id
                self.effect_count += 1
            if self.lose_first_post_response and not self._response_lost:
                self._response_lost = True
                raise TimeoutError("simulated response loss after durable accept")
            return {"run_id": run_id, "status": "started"}
        if method == "GET" and path == "/v1/runs/run-e11":
            return {
                "object": "hermes.run",
                "run_id": "run-e11",
                "status": "completed",
                "session_id": self.returned_session_id,
                "output": "E11 durable final",
                "assistant_message_id": "assistant-e11",
            }
        if "/messages" in path or "/chat" in path:
            raise AssertionError("durable result recovery must not scrape session messages or use chat")
        raise AssertionError(f"unexpected request: {method} {path}")


class _HistoryTrapGateway:
    durable_correlation = True

    def __init__(self) -> None:
        self.history_calls = 0

    def submit(self, **kwargs):
        del kwargs
        raise AssertionError("submit is not used in this unit contract")

    def history(self, *, session_key, marker):
        del session_key, marker
        return None

    def history_messages(self, *, session_key, marker):
        del session_key, marker
        self.history_calls += 1
        raise AssertionError("durable results must not enter legacy history recovery")


class E11DurableResultRecoveryTests(unittest.TestCase):
    def test_conversation_key_is_loaded_as_a_distinct_gateway_binding(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            config_path = Path(raw) / "recorder.toml"
            config_path.write_text(
                "[providers]\n"
                f'hermes_conversation_key = "{CONVERSATION_KEY}"\n',
                encoding="utf-8",
            )
            config = RecorderConfig.from_file(config_path)

        self.assertEqual(config.hermes_conversation_key, CONVERSATION_KEY)

    def test_distinct_conversation_key_binds_exact_target_without_legacy_routes(self) -> None:
        gateway = _DurableRunGateway()
        accepted_run_ids: list[str] = []

        result = gateway.submit(
            session_key=TARGET_SESSION_ID,
            request={"input": "E11 durable request"},
            submission_id=SUBMISSION_ID,
            marker="marker-e11",
            context=_context(),
            on_run_accepted=lambda run_id: accepted_run_ids.append(run_id) is None,
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.content, "E11 durable final")
        self.assertEqual(result.session_key, TARGET_SESSION_ID)
        self.assertEqual(result.run_id, "run-e11")
        self.assertEqual(accepted_run_ids, ["run-e11"])
        self.assertEqual(gateway.effect_count, 1)
        self.assertEqual(gateway.created_run_ids, {SUBMISSION_ID: "run-e11"})
        self.assertTrue(all(call[3]["X-Hermes-Session-Key"] == CONVERSATION_KEY for call in gateway.calls))
        post = next(call for call in gateway.calls if call[0:2] == ("POST", "/v1/runs"))
        assert post[2] is not None
        self.assertEqual(post[2]["session_id"], TARGET_SESSION_ID)
        self.assertFalse(any("/messages" in path or "/chat" in path for _, path, _, _ in gateway.calls))

    def test_post_response_loss_recovers_same_run_without_duplicate_effect(self) -> None:
        gateway = _DurableRunGateway()
        gateway.lose_first_post_response = True

        result = gateway.submit(
            session_key=TARGET_SESSION_ID,
            request={"input": "E11 durable request"},
            submission_id=SUBMISSION_ID,
            marker="marker-e11",
            context=_context(),
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.content, "E11 durable final")
        self.assertEqual(gateway.effect_count, 1)
        self.assertEqual(
            [path for method, path, _, _ in gateway.calls if method == "POST"],
            ["/v1/runs", "/v1/runs"],
        )

    def test_mismatched_result_session_fails_closed(self) -> None:
        gateway = _DurableRunGateway(returned_session_id="wrong-session")

        result = gateway.submit(
            session_key=TARGET_SESSION_ID,
            request={"input": "E11 durable request"},
            submission_id=SUBMISSION_ID,
            marker="marker-e11",
            context=_context(),
        )

        self.assertIsNone(result)
        self.assertEqual(gateway.effect_count, 1)

    def test_durable_result_path_never_requeries_legacy_message_history(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            gateway = _HistoryTrapGateway()
            service = RecorderService(
                RecorderStore(root / "recorder.sqlite3", storage_root=root / "data"),
                hermes=gateway,
            )
            with patch.object(service.store, "get_turn", return_value={"final_event_version": 1}):
                combined = service._requery_combined_content(
                    ingress={
                        "final_event_version": 1,
                        "gateway_session_key": TARGET_SESSION_ID,
                        "marker": "marker-e11",
                        "canonical_request_sha256": "a" * 64,
                        "hermes_submission_id": SUBMISSION_ID,
                        "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890e1",
                    },
                    result=HermesResult(
                        "assistant-e11",
                        "E11 durable final",
                        run_id="run-e11",
                        submission_id=SUBMISSION_ID,
                        turn_id="018f5a2e-7b6e-7abc-8d11-1234567890e1",
                        marker="marker-e11",
                        session_key=TARGET_SESSION_ID,
                        request_sha256="a" * 64,
                        subject_kind="turn",
                    ),
                )

        self.assertIsNone(combined)
        self.assertEqual(gateway.history_calls, 0)


if __name__ == "__main__":
    unittest.main()
