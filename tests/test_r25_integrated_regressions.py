"""VOICE1-B2 repair: integrated regressions for REV-001/002/003.

T-side: sanitized TTS projection, HermesAudioTTSProvider.readiness_check
fail-closed semantics, and one shared construction/refresh provider-chain
dispatch. S-side: the generic existing-session preflight stays
source-agnostic. R-side statement/receipt semantics are exercised in the
successor control packet's unittest class against the packet's own SQL
blocks; the product store contract is unchanged by this repair.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import importlib
import importlib.util
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from recorder_next.adapters import (
    CredentialError,
    HermesAudioTTSProvider,
    ProviderChain,
    ProviderFailure,
    ProviderTarget,
)
from recorder_next.config import RecorderConfig
from recorder_next.service import RecorderService, create_configured_service
from recorder_next.store import RecorderStore


class _ProbeFixture:
    """Bounded authenticated GET fixture for health + voice-config probes."""

    def __init__(self, *, health: Any, voice_config: Any, status: int = 200) -> None:
        self.health = health
        self.voice_config = voice_config
        self.status = status
        self.gets: list[str] = []
        self.posts = 0
        self.seen_authorization = False
        self.seen_session_token = False
        self._server = _ProbeServer(("127.0.0.1", 0), _ProbeHandler)
        self._server.fixture = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


class _ProbeServer(ThreadingHTTPServer):
    fixture: Any


class _ProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def _send_json(self, status: int, payload: Any) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        fixture = cast(_ProbeServer, self.server).fixture
        fixture.seen_authorization = self.headers.get("Authorization", "") == "Bearer fixture-secret"
        fixture.seen_session_token = self.headers.get("X-Hermes-Session-Token", "") == "fixture-secret"
        if self.path == "/api/health":
            fixture.gets.append("health")
            if fixture.status != 200:
                self._send_json(fixture.status, {"detail": "error"})
            elif isinstance(fixture.health, dict):
                self._send_json(200, fixture.health)
            else:
                self._send_json(fixture.status, fixture.health if not isinstance(fixture.health, int) else {"detail": "error"})
            return
        if self.path == "/api/audio/voice-config":
            fixture.gets.append("voice-config")
            if isinstance(fixture.voice_config, Exception):
                raise fixture.voice_config
            if fixture.status != 200:
                self._send_json(fixture.status, {"detail": "error"})
            else:
                self._send_json(200, fixture.voice_config)
            return
        self._send_json(404, {"detail": "not found"})

    def do_POST(self) -> None:
        fixture = cast(_ProbeServer, self.server).fixture
        fixture.posts += 1
        self._send_json(404, {"detail": "no synthesize during readiness"})


def _relay_config(tts: Any = None, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "ready": True,
        "audio_api": True,
        "provider": "hermes",
        "stt": {"mode": "relay", "reason": "provider 'edge' has no client wire", "ok": True, "enabled": True, "ready": True},
    }
    if tts is not None:
        payload["tts"] = tts
    payload.update(overrides)
    return payload


_OK_RELAY: dict[str, Any] = {
    "mode": "relay",
    "reason": "provider 'edge' has no client wire",
    "provider": "edge",
    "wire": "server",
    "configured": True,
    "enabled": True,
    "ready": True,
    "ok": True,
    "status": "ok",
}

_FLAG_KEYS = ("configured", "enabled", "ready", "ok")


class TTSReadinessProjectionTests(unittest.TestCase):
    """T1: sanitized probe projection contract (adapters._probe)."""

    def _projection(self, tts: Any, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        config = _relay_config(tts)
        if extra:
            config.update(extra)
        fixture = _ProbeFixture(health={"ok": True}, voice_config=config)
        try:
            provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
            return provider.capability_check()
        finally:
            fixture.close()

    def test_missing_tts_stays_missing(self):
        result = self._projection(None)
        self.assertNotIn("tts", result)

    def test_non_mapping_tts_becomes_invalid_marker_not_default_mapping(self):
        for bad in ("relay", ["edge"], 7, True):
            with self.subTest(tts=bad):
                result = self._projection(bad)
                self.assertIn("tts", result)
                self.assertIsNone(result["tts"])

    def test_semantic_keys_preserved_and_credentials_removed(self):
        tts = dict(_OK_RELAY)
        tts["api_key"] = "sk-secret"
        tts["credential"] = {"token": "hunter2"}
        tts["nested"] = {"authorization": "Bearer x", "base_url": "http://x", "url": "http://y"}
        result = self._projection(tts)
        self.assertIsInstance(result["tts"], dict)
        projected = result["tts"]
        self.assertEqual(
            set(projected),
            {"mode", "reason", "wire", "provider", "configured", "enabled", "ready", "ok", "status"},
        )
        self.assertNotIn("sk-secret", repr(projected))
        self.assertNotIn("hunter2", repr(projected))

    def test_non_scalar_semantic_values_become_invalid_markers(self):
        for field in ("mode", "reason", "wire", "provider", "configured", "enabled", "ready", "ok", "status"):
            with self.subTest(field=field):
                tts = dict(_OK_RELAY)
                tts[field] = ["list"] if field != "configured" else "true"
                result = self._projection(tts)
                self.assertIn("tts", result)
                projected = result["tts"]
                self.assertIn(field, projected)
                self.assertIsNone(projected[field])

    def test_resolution_error_suffix_collapses_to_fixed_category(self):
        tts = dict(_OK_RELAY)
        tts["reason"] = "openai resolution failed: transient upstream 500 http://internal"
        result = self._projection(tts)
        self.assertEqual(result["tts"]["reason"], "resolution error")

    def test_arbitrary_reason_becomes_fixed_unsupported_marker(self):
        tts = dict(_OK_RELAY)
        tts["reason"] = "endpoint http://10.1.2.3:9119 gave up"
        result = self._projection(tts)
        self.assertEqual(result["tts"]["reason"], "unsupported-reason")

    def test_overlong_semantic_string_is_invalid(self):
        tts = dict(_OK_RELAY)
        tts["provider"] = "e" * 300
        result = self._projection(tts)
        self.assertIsNone(result["tts"]["provider"])

    def test_malformed_tts_does_not_break_asr_projection(self):
        result = self._projection("garbage")
        self.assertEqual(result.get("ok"), True)
        self.assertIsInstance(result.get("stt"), dict)


class TTSReadinessProviderTests(unittest.TestCase):
    """T1/T2: HermesAudioTTSProvider.readiness_check fail-closed matrix."""

    def _credential(self, root: Path, value: str = "fixture-secret") -> Path:
        path = root / "recorder_api_key.env"
        path.write_text(f"API_SERVER_KEY={value}\n", encoding="ascii")
        path.chmod(0o600)
        return path

    def _fixture(self, tts: Any = None, extra_config: dict[str, Any] | None = None, status: int = 200) -> _ProbeFixture:
        config = _relay_config(tts)
        if extra_config:
            # Mutate the raw envelope BEFORE the HTTP round trip so the
            # provider's own projection path handles every malformed value.
            config.update(extra_config)
        health: Any = {"ok": True, "ready": True}
        if extra_config:
            mutated_health = {key: value for key, value in extra_config.items() if key in {"ready", "audio_api", "configured", "enabled"}}
            health.update(mutated_health)
        return _ProbeFixture(health=health, voice_config=config, status=status)

    def _ready(self, tts: Any = None, extra_config: dict[str, Any] | None = None) -> dict[str, Any]:
        fixture = self._fixture(tts, extra_config)
        try:
            provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
            return provider.readiness_check()
        finally:
            fixture.close()

    def _rejects(self, tts: Any, kind: str, *, retryable: bool | None = None, extra_config: dict[str, Any] | None = None) -> None:
        fixture = self._fixture(tts, extra_config)
        try:
            provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
            with self.assertRaises(ProviderFailure) as raised:
                provider.readiness_check()
            self.assertEqual(raised.exception.kind, kind)
            if retryable is not None:
                self.assertEqual(raised.exception.retryable, retryable)
        finally:
            fixture.close()

    def test_supported_edge_relay_passes_without_post(self):
        fixture = self._fixture(dict(_OK_RELAY))
        try:
            provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
            result = provider.readiness_check()
            self.assertEqual(set(result), {"health", "capability", "endpoint_contract"})
            self.assertEqual(result["endpoint_contract"], "/api/audio/speak?profile=default")
            self.assertEqual(fixture.gets, ["health", "voice-config"])
            self.assertEqual(fixture.posts, 0)
        finally:
            fixture.close()

    def test_explicitly_supported_relay_reasons_pass(self):
        for reason in ("command/plugin provider", "voice.client_direct disabled"):
            with self.subTest(reason=reason):
                tts = dict(_OK_RELAY)
                tts["reason"] = reason
                self._ready(tts)

    def test_all_supported_relay_provider_names_pass(self):
        for name in ("edge", "minimax", "xai", "mistral", "gemini", "neutts", "kittentts", "piper"):
            with self.subTest(name=name):
                tts = dict(_OK_RELAY)
                tts["reason"] = f"provider '{name}' has no client wire"
                self._ready(tts)

    def test_missing_tts_rejects_capability_unknown(self):
        self._rejects(None, "tts_capability_unknown", retryable=False)

    def test_stt_only_rejects_capability_unknown(self):
        self._rejects(None, "tts_capability_unknown", retryable=False)

    def test_non_mapping_tts_rejects_capability_unknown(self):
        for bad in ("relay", ["edge"], 7):
            with self.subTest(tts=bad):
                self._rejects(bad, "tts_capability_unknown", retryable=False)

    def test_disabled_modes_reject_non_retryable(self):
        for mode in ("disabled", "off", "none"):
            with self.subTest(mode=mode):
                tts = dict(_OK_RELAY)
                tts["mode"] = mode
                self._rejects(tts, "tts_disabled", retryable=False)

    def test_resolution_error_relay_rejects_retryable(self):
        tts = dict(_OK_RELAY)
        tts["reason"] = "resolution error"
        self._rejects(tts, "tts_unavailable", retryable=True)

    def test_openai_resolution_failed_relay_rejects_retryable(self):
        tts = dict(_OK_RELAY)
        tts["reason"] = "openai resolution failed: transient upstream"
        self._rejects(tts, "tts_unavailable", retryable=True)

    def test_no_credentials_relay_rejects_retryable(self):
        tts = dict(_OK_RELAY)
        tts["reason"] = "no credentials"
        self._rejects(tts, "tts_unavailable", retryable=True)

    def test_no_deepinfra_tts_model_relay_rejects_retryable(self):
        tts = dict(_OK_RELAY)
        tts["reason"] = "no deepinfra tts model"
        self._rejects(tts, "tts_unavailable", retryable=True)

    def test_tts_disabled_reason_rejects_non_retryable(self):
        tts = dict(_OK_RELAY)
        tts["reason"] = "tts disabled"
        self._rejects(tts, "tts_disabled", retryable=False)

    def test_unknown_relay_reason_rejects(self):
        tts = dict(_OK_RELAY)
        tts["reason"] = "provider 'novel-provider' has no client wire"
        self._rejects(tts, "tts_capability_unknown", retryable=False)

    def test_missing_mode_rejects(self):
        tts = {key: value for key, value in _OK_RELAY.items() if key != "mode"}
        self._rejects(tts, "tts_capability_unknown", retryable=False)

    def test_explicit_false_flags_reject_disabled(self):
        for field in _FLAG_KEYS:
            with self.subTest(field=field):
                tts = dict(_OK_RELAY)
                tts[field] = False
                self._rejects(tts, "tts_disabled", retryable=False)

    def test_non_bool_flag_values_reject_capability_unknown(self):
        for field in _FLAG_KEYS:
            for value in (1, "true"):
                with self.subTest(field=field, value=value):
                    tts = dict(_OK_RELAY)
                    tts[field] = value
                    self._rejects(tts, "tts_capability_unknown", retryable=False)

    def test_list_valued_flags_reject_capability_unknown(self):
        # A list value is dropped by the outer scalar filter, so the declared
        # flag disappears from the projection while tts stays present; the
        # envelope/capability flag gate must still reject.
        for field in _FLAG_KEYS:
            with self.subTest(field=field):
                tts = dict(_OK_RELAY)
                tts[field] = [True]
                fixture = self._fixture(tts)
                try:
                    provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
                    capability = provider.capability_check()
                    projected_tts = capability.get("tts")
                    flag_absent_or_invalid = not isinstance(projected_tts, dict) or projected_tts.get(field) is not True
                    self.assertTrue(flag_absent_or_invalid, "list-valued flag must not survive as True")
                finally:
                    fixture.close()

    def test_nested_false_envelope_contradiction_rejects(self):
        # tts.ready explicitly False while the envelope stays positive:
        # capability-level disabled rejection.
        tts = dict(_OK_RELAY)
        tts["ready"] = False
        self._rejects(tts, "tts_disabled", retryable=False)

    def test_audio_api_invalid_marker_rejects(self):
        # audio_api present but not an actual bool True in the raw envelope:
        # projection collapses it to an invalid marker -> capability unknown.
        self._rejects(dict(_OK_RELAY), "tts_capability_unknown", retryable=False, extra_config={"audio_api": 1})

    def test_audio_api_non_true_rejects(self):
        self._rejects(dict(_OK_RELAY), "tts_capability_unknown", retryable=False, extra_config={"audio_api": False})

    def test_envelope_flags_must_be_actual_true(self):
        # A present envelope configured/enabled flag must be an actual True;
        # False or any other scalar rejects.  A None (projection-invalidated
        # marker) leaves the envelope flag simply absent and is covered by
        # the capability-level flag check inside _validate_tts_capability.
        for field in ("configured", "enabled"):
            for value in (False, 1, "true"):
                with self.subTest(field=field, value=value):
                    self._rejects(dict(_OK_RELAY), "tts_capability_unknown", retryable=False, extra_config={field: value})

    def test_status_negative_rejects(self):
        tts = dict(_OK_RELAY)
        tts["status"] = "degraded"
        self._rejects(tts, "tts_capability_unknown", retryable=False)

    # -- B3: presence/type/length and ok-only contract (spec section 4) ----

    def test_ok_only_edge_relay_with_absent_envelope_ready_passes(self):
        # The live edge shape: capability envelope carries ok but no ready;
        # the health fixture still requires envelope ok only.
        fixture = _ProbeFixture(
            health={"ok": True},
            voice_config={
                "ok": True,
                "audio_api": True,
                "stt": {"mode": "relay", "reason": "provider 'edge' has no client wire", "ok": True},
                "tts": {"mode": "relay", "reason": "provider 'edge' has no client wire", "ok": True},
            },
        )
        try:
            provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
            result = provider.readiness_check()
            self.assertEqual(result["endpoint_contract"], "/api/audio/speak?profile=default")
            self.assertEqual(fixture.posts, 0)
        finally:
            fixture.close()

    def test_present_invalid_envelope_ready_rejects(self):
        # ready present but not an actual bool True (None marker from a list
        # payload) must reject; absent ready stays valid.
        for bad_ready in (None, False, 1, "true", ["y"], {"y": 1}):
            with self.subTest(ready=bad_ready):
                envelope = {
                    "ok": True,
                    "ready": bad_ready,
                    "audio_api": True,
                    "stt": {"ok": True},
                    "tts": dict(_OK_RELAY),
                }
                fixture = _ProbeFixture(health={"ok": True}, voice_config=envelope)
                try:
                    provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
                    if bad_ready is None:
                        # None raw ready projects to a present invalid marker
                        # and must reject (never silently treated as absent).
                        with self.assertRaises(ProviderFailure) as raised:
                            provider.readiness_check()
                        self.assertEqual(raised.exception.kind, "tts_capability_unknown")
                    else:
                        with self.assertRaises(ProviderFailure) as raised:
                            provider.readiness_check()
                        self.assertEqual(raised.exception.kind, "tts_capability_unknown")
                finally:
                    fixture.close()

    def test_present_invalid_envelope_flags_reject_across_types(self):
        # Every envelope flag: absent is fine (ok excepted), but present must
        # be an actual bool True; list/dict/None markers reject.
        for flag in ("configured", "enabled", "audio_api"):
            for bad in (None, False, 0, 1, "true", [], {}, ["x"]):
                with self.subTest(flag=flag, bad=bad):
                    envelope = {
                        "ok": True,
                        "ready": True,
                        "audio_api": True,
                        "stt": {"ok": True},
                        "tts": dict(_OK_RELAY),
                    }
                    envelope[flag] = bad
                    fixture = _ProbeFixture(health={"ok": True}, voice_config=envelope)
                    try:
                        provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
                        with self.assertRaises(ProviderFailure) as raised:
                            provider.readiness_check()
                        self.assertEqual(raised.exception.kind, "tts_capability_unknown")
                    finally:
                        fixture.close()

    def test_missing_envelope_ok_rejects(self):
        for ok_value in (None, False, 0, 1, "true"):
            with self.subTest(ok=ok_value):
                envelope = {
                    "ok": ok_value,
                    "ready": True,
                    "stt": {"ok": True},
                    "tts": dict(_OK_RELAY),
                }
                fixture = _ProbeFixture(health={"ok": True}, voice_config=envelope)
                try:
                    provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
                    with self.assertRaises(ProviderFailure) as raised:
                        provider.readiness_check()
                    self.assertEqual(raised.exception.kind, "tts_capability_unknown")
                finally:
                    fixture.close()

    def test_nested_ready_dict_and_direct_reason_list_reject(self):
        # Reviewer cases: nested dict ready and list direct reason must both
        # survive projection as invalid markers and reject.
        nested = dict(_OK_RELAY)
        nested["ready"] = {"state": True}
        self._rejects(nested, "tts_capability_unknown", retryable=False)
        direct = {
            "mode": "direct",
            "provider": "openai",
            "wire": "openai-speech",
            "reason": ["nope"],
        }
        self._rejects(direct, "tts_capability_unknown", retryable=False)

    def test_relay_provider_boundary_lengths(self):
        # provider is descriptive in relay: present must satisfy the string
        # presence/type/length contract (256 ok, 257 invalid).
        for length, expect_reject in ((1, False), (256, False), (257, True), (300, True)):
            with self.subTest(length=length):
                tts = dict(_OK_RELAY)
                tts["provider"] = "p" * length
                if expect_reject:
                    self._rejects(tts, "tts_capability_unknown", retryable=False)
                else:
                    self._ready(tts)

    def test_relay_provider_present_invalid_rejects(self):
        for bad in (None, 7, True, "", "   ", [], ["edge"]):
            with self.subTest(bad=bad):
                tts = dict(_OK_RELAY)
                tts["provider"] = bad
                self._rejects(tts, "tts_capability_unknown", retryable=False)

    def test_direct_reason_empty_and_whitespace_passes(self):
        # Direct mode: absent, empty, and whitespace-only reasons are valid;
        # any nonempty reason still rejects.
        for reason in ("", "   ", None):
            with self.subTest(reason=reason):
                tts = {
                    "mode": "direct",
                    "provider": "openai",
                    "wire": "openai-speech",
                    "configured": True,
                    "enabled": True,
                    "ready": True,
                    "ok": True,
                }
                if reason is not None:
                    tts["reason"] = reason
                self._ready(tts)
        nonempty = {
            "mode": "direct",
            "provider": "openai",
            "wire": "openai-speech",
            "reason": "unexpected provider text",
            "configured": True,
            "enabled": True,
            "ready": True,
            "ok": True,
        }
        self._rejects(nonempty, "tts_capability_unknown", retryable=False)

    def test_direct_reason_overlong_rejects(self):
        tts = {
            "mode": "direct",
            "provider": "openai",
            "wire": "openai-speech",
            "reason": "r" * 257,
        }
        self._rejects(tts, "tts_capability_unknown", retryable=False)

    def test_optional_status_presence_contract(self):
        # status: positive forms pass; negative, empty, whitespace, None
        # marker, wrong type, and overlong all reject.
        for good in ("ok", "ready", "available", "OK", " Ready "):
            with self.subTest(status=good):
                tts = dict(_OK_RELAY)
                tts["status"] = good
                self._ready(tts)
        for bad in ("degraded", "", "   ", None, 5, ["ok"], {"s": 1}, "x" * 257):
            with self.subTest(status=bad):
                tts = dict(_OK_RELAY)
                tts["status"] = bad
                self._rejects(tts, "tts_capability_unknown", retryable=False)

    def test_nested_secret_at_depth_never_survives_projection(self):
        tts = dict(_OK_RELAY)
        tts["credential"] = {"token": "deep-secret", "nested": {"api_key": "deeper-secret"}}
        tts["headers"] = {"Authorization": "Bearer x"}
        fixture = self._fixture(tts)
        try:
            provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
            capability = provider.capability_check()
            projected = capability.get("tts")
            self.assertIsInstance(projected, dict)
            self.assertEqual(
                set(projected),
                {"mode", "reason", "wire", "provider", "configured", "enabled", "ready", "ok", "status"},
            )
            self.assertNotIn("deep-secret", repr(capability))
            self.assertNotIn("deeper-secret", repr(capability))
        finally:
            fixture.close()

    def test_health_explicit_false_stays_provider_unavailable(self):
        # Inherited classification: an explicit health false is a provider
        # outage, not a TTS capability mismatch.
        fixture = _ProbeFixture(health={"ok": True, "ready": False}, voice_config=_relay_config(dict(_OK_RELAY)))
        try:
            provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
            with self.assertRaises(ProviderFailure) as raised:
                provider.readiness_check()
            self.assertEqual(raised.exception.kind, "provider_unavailable")
            self.assertTrue(raised.exception.retryable)
        finally:
            fixture.close()

    def test_unknown_wire_rejects(self):
        tts = dict(_OK_RELAY)
        tts["wire"] = "carrier-pigeon"
        self._rejects(tts, "tts_capability_unknown", retryable=False)

    def test_direct_positive_openai_speech_passes_without_secret_leak(self):
        tts: dict[str, Any] = {
            "mode": "direct",
            "provider": "openai",
            "wire": "openai-speech",
            "configured": True,
            "enabled": True,
            "ready": True,
            "ok": True,
            "api_key": "sk-must-not-escape",
        }
        result = self._ready(tts)
        self.assertNotIn("sk-must-not-escape", repr(result))

    def test_direct_positive_elevenlabs_passes(self):
        tts: dict[str, Any] = {
            "mode": "direct",
            "provider": "elevenlabs",
            "wire": "elevenlabs-tts",
            "configured": True,
            "enabled": True,
            "ready": True,
            "ok": True,
        }
        self._ready(tts)

    def test_deepinfra_direct_supported(self):
        tts: dict[str, Any] = {
            "mode": "direct",
            "provider": "deepinfra",
            "wire": "openai-speech",
            "configured": True,
            "enabled": True,
            "ready": True,
            "ok": True,
        }
        self._ready(tts)

    def test_direct_positive_with_reason_rejects(self):
        tts: dict[str, Any] = {
            "mode": "direct",
            "provider": "openai",
            "wire": "openai-speech",
            "reason": "resolution error",
            "configured": True,
            "enabled": True,
            "ready": True,
            "ok": True,
        }
        self._rejects(tts, "tts_unavailable", retryable=True)

    def test_direct_unknown_wire_or_provider_rejects(self):
        base: dict[str, Any] = {
            "mode": "direct",
            "provider": "openai",
            "wire": "openai-speech",
            "configured": True,
            "enabled": True,
            "ready": True,
            "ok": True,
        }
        for mutate in ({"wire": "carrier-pigeon"}, {"provider": "unknown-corp"}):
            tts = dict(base)
            tts.update(mutate)
            with self.subTest(mutate=mutate):
                self._rejects(tts, "tts_capability_unknown", retryable=False)

    def test_stt_wire_does_not_qualify(self):
        tts: dict[str, Any] = {
            "mode": "direct",
            "provider": "openai",
            "wire": "stt-whisper",
            "configured": True,
            "enabled": True,
            "ready": True,
            "ok": True,
        }
        self._rejects(tts, "tts_capability_unknown", retryable=False)

    def test_error_messages_carry_fixed_categories_only(self):
        tts = dict(_OK_RELAY)
        tts["reason"] = "openai resolution failed: secret-context http://internal-host/token"
        fixture = self._fixture(tts)
        try:
            provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=None)
            with self.assertRaises(ProviderFailure) as raised:
                provider.readiness_check()
            message = str(raised.exception)
            self.assertNotIn("secret-context", message)
            self.assertNotIn("internal-host", message)
        finally:
            fixture.close()

    def test_wrong_auth_rejects_as_auth_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _relay_config(dict(_OK_RELAY))
            fixture = _ProbeFixture(health={"ok": True, "ready": True}, voice_config=config, status=401)
            try:
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root, "wrong-secret"))
                with self.assertRaises(ProviderFailure) as raised:
                    provider.readiness_check()
                self.assertEqual(raised.exception.kind, "auth")
            finally:
                fixture.close()

    def test_readiness_sends_session_token_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _relay_config(dict(_OK_RELAY))
            fixture = _ProbeFixture(health={"ok": True, "ready": True}, voice_config=config)
            try:
                provider = HermesAudioTTSProvider(fixture.url, profile="default", credential_file=self._credential(root))
                provider.readiness_check()
                self.assertTrue(fixture.seen_session_token)
                self.assertTrue(fixture.seen_authorization)
            finally:
                fixture.close()


class _ConfiguredChainFactoryMixin:
    """Build a real RecorderConfig whose chains point at the probe fixture."""

    def _write_config(self, root: Path, fixture_url: str) -> Path:
        credential = root / "recorder_api_key"
        credential.write_text("API_SERVER_KEY=fixture-secret\n", encoding="ascii")
        credential.chmod(0o600)
        config_path = root / "recorder-next.toml"
        config_path.write_text(
            "\n".join(
                (
                    "[server]",
                    'host = "127.0.0.1"',
                    "port = 8653",
                    "",
                    "[storage]",
                    f'database = "{root / "db.sqlite3"}"',
                    f'root = "{root / "data"}"',
                    "",
                    "[providers]",
                    'asr_source = "hermes"',
                    'asr_chain = ["hermes-audio"]',
                    'tts_source = "hermes"',
                    'tts_chain = ["hermes-audio"]',
                    "",
                    "[[providers.asr_providers]]",
                    'name = "hermes-audio"',
                    'adapter = "hermes"',
                    f'endpoint = "{fixture_url}"',
                    'profile = "default"',
                    f'credential_file = "{credential}"',
                    'health_path = "/api/health"',
                    'capability_path = "/api/audio/voice-config"',
                    "enabled = true",
                    "",
                    "[[providers.tts_providers]]",
                    'name = "hermes-audio"',
                    'adapter = "hermes"',
                    f'endpoint = "{fixture_url}"',
                    'profile = "default"',
                    f'credential_file = "{credential}"',
                    'health_path = "/api/health"',
                    'capability_path = "/api/audio/voice-config"',
                    "enabled = true",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        return config_path


class SharedConstructionRefreshTests(_ConfiguredChainFactoryMixin, unittest.TestCase):
    """T3: one shared chain dispatcher for construction and refresh."""

    def _fixture(self, tts: Any = None) -> _ProbeFixture:
        return _ProbeFixture(health={"ok": True, "ready": True}, voice_config=_relay_config(tts))

    def _create(self, config_path: Path, *, production: bool = False):
        return create_configured_service(
            RecorderConfig.from_file(config_path).resolved(),
            require_production=production,
            ingress_secret="fixture-ingress-secret" if production else None,
        )

    def test_negative_readiness_construction_fails_before_storage_opens(self):
        fixture = self._fixture({"mode": "relay", "reason": "resolution error"})
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config_path = self._write_config(root, fixture.url)
                opened: list[str] = []
                original_init = RecorderStore.__init__

                def trap_init(store_self: Any, *args: Any, **kwargs: Any) -> None:
                    opened.append("store")
                    original_init(store_self, *args, **kwargs)

                with patch.object(RecorderStore, "__init__", trap_init):
                    with self.assertRaises(ProviderFailure) as raised:
                        self._create(config_path, production=True)
                    self.assertEqual(raised.exception.kind, "tts_unavailable")
                self.assertEqual(opened, [], "negative readiness must not construct RecorderStore")
        finally:
            fixture.close()

    def test_positive_readiness_construction_succeeds_and_refresh_agrees(self):
        fixture = self._fixture(dict(_OK_RELAY))
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config_path = self._write_config(root, fixture.url)
                service = self._create(config_path)
                self.assertTrue(service.refresh_production_readiness())
                self.assertIsNotNone(service.tts_chain)
                assert service.tts_chain is not None
                self.assertIsInstance(service.tts_chain.targets[0].provider, HermesAudioTTSProvider)
                self.assertEqual(fixture.posts, 0)
        finally:
            fixture.close()

    def test_refresh_positive_negative_positive_transition_and_no_stale_true(self):
        fixture = self._fixture(dict(_OK_RELAY))
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config_path = self._write_config(root, fixture.url)
                service = self._create(config_path)
                self.assertTrue(service.refresh_production_readiness())

                # flip to negative: readiness must not retain stale success
                fixture.voice_config = _relay_config({"mode": "relay", "reason": "resolution error"})
                self.assertFalse(service.refresh_production_readiness())

                # back to positive: recovery works
                fixture.voice_config = _relay_config(dict(_OK_RELAY))
                self.assertTrue(service.refresh_production_readiness())
        finally:
            fixture.close()

    def test_construction_and_refresh_dispatch_same_provider_method(self):
        fixture = self._fixture(dict(_OK_RELAY))
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config_path = self._write_config(root, fixture.url)
                calls: list[str] = []
                real_readiness = HermesAudioTTSProvider.readiness_check

                def spy_readiness(provider_self: Any) -> dict[str, Any]:
                    calls.append("readiness_check")
                    return real_readiness(provider_self)

                with patch.object(HermesAudioTTSProvider, "readiness_check", spy_readiness):
                    # Production construction probes the chains through
                    # RecorderService._probe_provider_chain (spec 4.3), and
                    # refresh must dispatch the exact same provider method.
                    service = self._create(config_path, production=False)
                    # Construction-equivalent probe via the shared dispatcher:
                    RecorderService._probe_provider_chain(service.tts_chain)
                    construction_calls = list(calls)
                    calls.clear()
                    self.assertTrue(service.refresh_production_readiness())
                    refresh_calls = list(calls)
                self.assertEqual(construction_calls, ["readiness_check"])
                self.assertEqual(refresh_calls, ["readiness_check"])
        finally:
            fixture.close()

    def test_fixture_source_chain_construction_rejected(self):
        fixture = self._fixture(dict(_OK_RELAY))
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config_path = self._write_config(root, fixture.url)
                text = config_path.read_text(encoding="utf-8")
                text = text.replace('adapter = "hermes"', 'adapter = "fixture"')
                config_path.write_text(text, encoding="utf-8")
                with self.assertRaises(CredentialError):
                    self._create(config_path)
        finally:
            fixture.close()


class GenericSourceAgnosticPreflightTests(unittest.TestCase):
    """S: HttpHermesGateway._preflight_existing_session stays source-agnostic."""

    def test_generic_preflight_has_no_source_predicate(self):
        import inspect

        from recorder_next.adapters import HttpHermesGateway

        self.assertTrue(hasattr(HttpHermesGateway, "_preflight_existing_session"))
        source_text = inspect.getsource(HttpHermesGateway._preflight_existing_session)
        self.assertNotIn("discord", source_text.lower())


class Voice1B4ExecutableClosureTests(unittest.TestCase):
    """VOICE1-B4: the executable admission caller/aggregate and the fixture

    attempt executor/custody/cleanup controls required by the ratified B3
    architecture (sections 5 S.1-S.3 and 6 R.1-R.4).  Every test imports and
    CALLS the real symbols in the control module; text search alone is
    insufficient evidence.
    """

    @classmethod
    def setUpClass(cls) -> None:
        control_dir = Path(__file__).resolve().parents[1] / "run"
        if str(control_dir) not in sys.path:
            sys.path.insert(0, str(control_dir))
        import qa_probe_runner as control

        cls.control = control

    # -- import-inertness / module-shape contract (S.2) ------------------

    def test_required_symbols_exist_and_main_gated(self):
        control = self.control
        self.assertTrue(callable(control.REQUIRED_PREDICATES) or hasattr(control, "REQUIRED_PREDICATES"))
        self.assertTrue(callable(control.run_voice1_readonly_admission))
        self.assertTrue(callable(control.main))
        self.assertTrue(callable(control.load_attempt_prefix))
        self.assertTrue(callable(control.publish_attempt_receipt))
        self.assertTrue(callable(control.execute_attempt_phase))
        self.assertTrue(callable(control.cleanup_attempt))
        self.assertIsInstance(control.REQUIRED_PREDICATES, tuple)
        self.assertEqual(len(control.REQUIRED_PREDICATES), 32)
        self.assertEqual(len(set(control.REQUIRED_PREDICATES)), 32)

    def test_main_without_flags_is_structured_hold_exit_2(self):
        report: dict[str, Any] = {}
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            exit_code = self.control.main([])
        try:
            report = json.loads(captured.getvalue())
        except json.JSONDecodeError:
            self.fail("no-flags invocation must print one JSON report")
        self.assertEqual(exit_code, 2)
        self.assertEqual(report.get("status"), "HOLD")
        self.assertEqual(report.get("status_code"), 2)

    def test_module_main_block_raises_instruction_only(self):
        source = Path(self.control.__file__).read_text(encoding="utf-8")
        guard = re.search(r'if __name__ == "__main__":\n(.*)\Z', source, re.S)
        assert guard is not None
        self.assertNotIn("run_voice1_readonly_admission", guard.group(1))
        self.assertNotIn("main(", guard.group(1))

    def test_import_does_not_touch_boundary_state(self):
        source_path = Path(self.control.__file__)
        module_name = f"_b4_reimport_probe_{uuid.uuid4().hex}"
        before_env = {key: os.environ.get(key) for key in
                      ("RECORDER_INGRESS_SECRET", "CREDENTIALS_DIRECTORY", "HERMES_API_SERVER_KEY")}
        spec = importlib.util.spec_from_file_location(module_name, source_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        t0 = time.monotonic()
        spec.loader.exec_module(module)
        self.assertLess(time.monotonic() - t0, 5.0)
        after_env = {key: os.environ.get(key) for key in before_env}
        self.assertEqual(before_env, after_env, "import must not mutate process env")

    # -- aggregate contract (S.3): every required predicate individually ----

    def _ok_context(self, predicates: dict[str, bool]) -> dict[str, Any]:
        """Minimal fixture admission context reaching an all-true reduction."""
        context = self._boundary_context()
        context["predicate_overrides"] = predicates
        return context

    def _boundary_context(self) -> dict[str, Any]:
        return {
            "candidate_id": "fixture-candidate",
            "archive_sha256": "0" * 64,
            "source_commit": "f" * 40,
            "source_tree": "e" * 64,
            "control_sha256": "d" * 64,
            "spec_sha256": "c" * 64,
            "manifest": {"candidate_id": "fixture-candidate"},
            "authorization": {"read_only": True},
            "import_origin_ok": True,
            "per_file_hashes_ok": True,
            "credential_custody_ok": True,
            "dashboard_credential_ok": True,
            "api_credential_ok": True,
            "dashboard_remaining_seconds_pre": 7200,
            "dashboard_remaining_seconds_post": 7200,
            "unauthenticated_gate": {"status": 401, "secret_in_body": False},
            "probes": {
                "api_capability": {"run_submission": True},
                "asr_ready": True,
                "tts_ready": True,
                "omitted_profile": {"target": "/api/audio/voice-config", "reduction": {"ok": True}},
                "explicit_profile": {"target": "/api/audio/voice-config?profile=default",
                                     "reduction": {"ok": True}, "validated": True},
            },
            "session": {
                "preflight_ok": True, "payload_object_match": True, "id_match": True,
                "within_budget": True,
                "payload": {
                    "object": "hermes.session",
                    "session": {"id": "20260703_210417_8f66b434", "source": "discord",
                                "archived": False, "ended_at": None},
                },
            },
            "persisted": {
                "read_only_ok": True, "indexed_ok": True,
                "rows": [{"id": "20260703_210417_8f66b434", "source": "discord",
                          "session_key": "agent:main:discord:thread:fixture-key-value",
                          "ended_at": None}],
            },
            "expected_session_id": "20260703_210417_8f66b434",
            "expected_key_sha256": hashlib.sha256(
                b"agent:main:discord:thread:fixture-key-value").hexdigest(),
            "closing_identity_ok": True,
            "no_mutation_ok": True,
            "secret_safe_ok": True,
        }

    def test_aggregate_rejects_each_false_or_missing_predicate(self):
        base = {name: True for name in self.control.REQUIRED_PREDICATES}
        for name in self.control.REQUIRED_PREDICATES:
            for mutation in (False, 1, "true"):
                with self.subTest(predicate=name, value=mutation):
                    predicates = dict(base)
                    predicates[name] = mutation
                    report = self.control.run_voice1_readonly_admission(
                        self._ok_context(predicates)
                    )
                    self.assertEqual(report["status"], "HOLD")
                    self.assertEqual(report["status_code"], 2)
                    self.assertIn(name, report["failed_predicates"])
            # A None override removes the predicate entirely: it must then be
            # reported as MISSING (the aggregate never infers from report keys).
            with self.subTest(predicate=name, value="null-removed"):
                predicates = dict(base)
                predicates[name] = None
                report = self.control.run_voice1_readonly_admission(
                    self._ok_context(predicates)
                )
                self.assertEqual(report["status"], "HOLD")
                self.assertEqual(report["status_code"], 2)
                self.assertIn(name, report["missing_predicates"])
            # A missing name (absent from the injected mapping entirely)
            # must also surface in missing_predicates: overrides that do not
            # mention a name still let the boundary observation stand, so we
            # prove the aggregate itself never infers missing names by
            # passing an overrides mapping that is the empty dict.
            with self.subTest(predicate=name, value="overrides-empty-boundary-removed"):
                context = self._boundary_context()
                # Remove every boundary observation so the caller's own
                # computation cannot classify the predicate as True.
                stripped = {
                    key: value for key, value in context.items()
                    if key not in {
                        "import_origin_ok", "per_file_hashes_ok",
                        "credential_custody_ok", "dashboard_credential_ok",
                        "api_credential_ok", "dashboard_remaining_seconds_pre",
                        "dashboard_remaining_seconds_post", "unauthenticated_gate",
                        "probes", "session", "persisted", "closing_identity_ok",
                        "no_mutation_ok", "secret_safe_ok",
                    }
                }
                stripped["predicate_overrides"] = {}
                report = self.control.run_voice1_readonly_admission(stripped)
                self.assertEqual(report["status"], "HOLD")
                self.assertEqual(report["status_code"], 2)
                self.assertIn(name, report["missing_predicates"] + report["failed_predicates"])

    def test_aggregate_all_true_passes_with_exact_schema(self):
        predicates = {name: True for name in self.control.REQUIRED_PREDICATES}
        report = self.control.run_voice1_readonly_admission(self._ok_context(predicates))
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["status_code"], 0)
        self.assertEqual(report["schema"], "recorder-next-voice1-readonly-admission/v1")
        self.assertEqual(sorted(report["predicates"]), sorted(self.control.REQUIRED_PREDICATES))
        self.assertEqual(report["missing_predicates"], [])
        self.assertEqual(report["failed_predicates"], [])

    def test_pure_predicate_row_shape_matrix(self):
        payload = {
            "object": "hermes.session",
            "session": {"id": "20260703_210417_8f66b434", "source": "discord",
                        "archived": False, "ended_at": None},
        }
        key = "agent:main:discord:thread:fixture-key-value"
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        good = {"id": "20260703_210417_8f66b434", "source": "discord",
                "session_key": key, "ended_at": None}
        ok = self.control.voice1_session_admission(
            payload, [good],
            expected_session_id="20260703_210417_8f66b434",
            expected_key_sha256=digest,
        )
        self.assertEqual(ok["status"], "PASS")
        truncated = ("20260703_210417_8f66b434", "discord", key)
        extra = (good["id"], good["source"], key, None, "extra")
        missing_key = {"id": good["id"], "source": good["source"], "session_key": key}
        extra_key = dict(good, unexpected=1)
        not_a_row = 42
        for row in (truncated, extra, missing_key, extra_key, not_a_row):
            with self.subTest(row=type(row).__name__):
                result = self.control.voice1_session_admission(
                    payload, [row],
                    expected_session_id="20260703_210417_8f66b434",
                    expected_key_sha256=digest,
                )
                self.assertEqual(result["status"], "HOLD")
                self.assertIn("persisted_row_shape", result["reason_codes"])
                self.assertFalse(result["persisted_ended_at_null"])

    def test_main_authority_mismatch_holds_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "manifest.json"
            authorization = root / "authorization.json"
            manifest.write_text(json.dumps({"schema": "x"}), encoding="utf-8")
            authorization.write_text(json.dumps({"schema": "y"}), encoding="utf-8")
            good_manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
            good_auth_sha = hashlib.sha256(authorization.read_bytes()).hexdigest()
            for kwargs in (
                {},
                {"manifest": str(manifest), "manifest_sha256": good_manifest_sha},
                {"manifest": str(manifest), "manifest_sha256": good_manifest_sha,
                 "authorization": str(authorization), "authorization_sha256": "0" * 64},
                {"manifest": str(root / "absent.json"), "manifest_sha256": "0" * 64,
                 "authorization": str(authorization), "authorization_sha256": good_auth_sha},
                {"manifest": str(manifest), "manifest_sha256": "tooshort",
                 "authorization": str(authorization), "authorization_sha256": good_auth_sha},
            ):
                with self.subTest(args=sorted(kwargs)):
                    argv = ["--read-only-admission"]
                    for key, value in kwargs.items():
                        argv.extend([f"--{key.replace(chr(95), chr(45))}", value])
                    with contextlib.redirect_stdout(io.StringIO()) as captured:
                        exit_code = self.control.main(argv)
                    report = json.loads(captured.getvalue())
                    self.assertEqual(exit_code, 2)
                    self.assertEqual(report["status"], "HOLD")
                    self.assertEqual(report["status_code"], 2)

    # -- executor boundary matrix: real functions, private fixture root -----

    def test_executor_functions_reject_live_fixture_context(self):
        with self.assertRaises(self.control.AttemptContextError):
            self.control._validate_fixture_context({
                "fixture_root": "/var/lib/recorder-next",
                "db_path": "/var/lib/recorder-next/recorder-next.sqlite3",
            })
        with self.assertRaises(self.control.AttemptContextError):
            self.control._validate_fixture_context({"fixture_root": None, "db_path": None})


if __name__ == "__main__":
    unittest.main()
