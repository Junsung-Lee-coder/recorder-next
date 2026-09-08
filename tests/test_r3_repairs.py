from __future__ import annotations

import io
import urllib.error
import unittest
import warnings
from email.message import Message
from unittest.mock import patch

from recorder_next.adapters import HttpHermesGateway, ProviderFailure, _HTTPProvider


class HttpErrorResourceRegressionTests(unittest.TestCase):
    @staticmethod
    def _http_error(path: str, status: int, body_text: str) -> tuple[urllib.error.HTTPError, io.BytesIO]:
        body = io.BytesIO(body_text.encode("utf-8"))
        error = urllib.error.HTTPError(path, status, "failure", Message(), body)
        return error, body

    @staticmethod
    def _strict_call(callback):
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            return callback()

    def _provider(self, *, health_path: str | None = None) -> _HTTPProvider:
        return _HTTPProvider(
            "http://127.0.0.1:9/tts",
            timeout=1,
            credential_file=None,
            health_path=health_path,
        )

    def test_request_closes_http_error_response_before_classifying(self) -> None:
        body = io.BytesIO(b"request failure")
        error = urllib.error.HTTPError("http://127.0.0.1:9/tts", 503, "unavailable", Message(), body)

        with patch("recorder_next.adapters._urlopen_no_redirect", side_effect=error):
            with self.assertRaises(ProviderFailure) as raised:
                self._provider()._request({"text": "probe"})

        self.assertEqual(raised.exception.kind, "server")
        self.assertTrue(body.closed)
        self.assertTrue(error.closed)

    def test_probe_closes_http_error_response_before_classifying(self) -> None:
        body = io.BytesIO(b"probe failure")
        error = urllib.error.HTTPError("http://127.0.0.1:9/health", 404, "missing", Message(), body)

        with patch("recorder_next.adapters._urlopen_no_redirect", side_effect=error):
            with self.assertRaises(ProviderFailure) as raised:
                self._provider(health_path="/health").health_check()

        self.assertEqual(raised.exception.kind, "client")
        self.assertTrue(body.closed)
        self.assertTrue(error.closed)

    def test_gateway_closes_http_error_response_before_fallback(self) -> None:
        error, body = self._http_error("http://127.0.0.1:9/api/sessions", 500, "gateway failure")
        gateway = HttpHermesGateway("http://127.0.0.1:9")

        with patch.object(gateway, "_request", side_effect=error):
            result = self._strict_call(
                lambda: gateway.submit(
                    session_key="session", request={"input": "probe"}, submission_id="submission", marker="marker"
                )
            )

        self.assertIsNone(result)
        self.assertTrue(body.closed)
        self.assertTrue(error.closed)

    def test_gateway_closes_retry_http_error_after_create_success(self) -> None:
        initial, initial_body = self._http_error("http://127.0.0.1:9/api/sessions/session/chat", 404, "missing")
        retry, retry_body = self._http_error("http://127.0.0.1:9/api/sessions/session/chat", 503, "retry failure")
        gateway = HttpHermesGateway("http://127.0.0.1:9")

        with patch.object(gateway, "_request", side_effect=[initial, {}, retry]) as request:
            result = self._strict_call(
                lambda: gateway.submit(
                    session_key="session", request={"input": "probe"}, submission_id="submission", marker="marker"
                )
            )

        self.assertIsNone(result)
        self.assertEqual(request.call_count, 3)
        self.assertTrue(initial.closed)
        self.assertTrue(initial_body.closed)
        self.assertTrue(retry.closed)
        self.assertTrue(retry_body.closed)

    def test_gateway_closes_retry_http_error_after_create_conflict(self) -> None:
        initial, initial_body = self._http_error("http://127.0.0.1:9/api/sessions/session/chat", 404, "missing")
        create, create_body = self._http_error("http://127.0.0.1:9/api/sessions", 409, "exists")
        retry, retry_body = self._http_error("http://127.0.0.1:9/api/sessions/session/chat", 503, "retry failure")
        gateway = HttpHermesGateway("http://127.0.0.1:9")

        with patch.object(gateway, "_request", side_effect=[initial, create, retry]) as request:
            result = self._strict_call(
                lambda: gateway.submit(
                    session_key="session", request={"input": "probe"}, submission_id="submission", marker="marker"
                )
            )

        self.assertIsNone(result)
        self.assertEqual(request.call_count, 3)
        for resource in (initial, create, retry, initial_body, create_body, retry_body):
            self.assertTrue(resource.closed)

    def test_gateway_closes_history_http_error_response_and_body(self) -> None:
        error, body = self._http_error("http://127.0.0.1:9/api/sessions/session/messages", 500, "history failure")
        gateway = HttpHermesGateway("http://127.0.0.1:9")

        with patch.object(gateway, "_request", side_effect=error):
            result = self._strict_call(
                lambda: gateway.history_messages(session_key="session", marker="marker")
            )

        self.assertEqual(result, [])
        self.assertTrue(error.closed)
        self.assertTrue(body.closed)


if __name__ == "__main__":
    unittest.main()
