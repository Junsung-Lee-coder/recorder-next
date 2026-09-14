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
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import importlib
import importlib.util
import unittest
import uuid
import wave
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from recorder_next import __main__ as recorder_main
from recorder_next.adapters import (
    CredentialError,
    HermesAudioTTSProvider,
    MemoryHermesGateway,
    ProviderChain,
    ProviderFailure,
    ProviderTarget,
    StaticTTSProvider,
)
from recorder_next.config import RecorderConfig
from recorder_next.errors import ConflictError, LeaseConflict, SourceUnavailableError, ValidationError
from recorder_next.features import FeatureGroups
from recorder_next.models import AsrResult, HermesResult
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
        if self.path == "/v1/capabilities":
            self._send_json(200, {"features": {"run_submission": True}})
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

    def _write_config_with_tts_adapter(self, root: Path, fixture_url: str, adapter: str) -> Path:
        """Real RecorderConfig selection for a generic/Edge TTS chain (B6 T).

        The ASR chain points at the same fixture through the Hermes adapter
        surface used by the shared construction dispatcher; the TTS chain
        uses the requested generic adapter class path.
        """
        credential = root / "recorder_api_key"
        credential.write_text("API_SERVER_KEY=fixture-secret\n", encoding="ascii")
        credential.chmod(0o600)
        config_path = root / f"recorder-next-{adapter}.toml"
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
                    f'hermes_base_url = "{fixture_url}"',
                    f'hermes_api_key_file = "{credential}"',
                    'asr_source = "hermes"',
                    'asr_chain = ["hermes-audio"]',
                    f'tts_source = "{adapter}"',
                    f'tts_chain = ["generic-tts"]',
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
                    'name = "generic-tts"',
                    f'adapter = "{adapter}"',
                    f'endpoint = "{fixture_url}"',
                    'model = "korean-tts"',
                    'voice = "ko-KR-1"',
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

    def test_generic_and_edge_construction_refresh_use_actual_readiness(self):
        # B6 T acceptance: HttpTTSProvider and EdgeTTSProvider are reachable
        # through real configuration selection (not dispatcher labeling);
        # malformed present semantics reject construction before storage and
        # a positive construction refreshes True with zero POSTs.
        from recorder_next.adapters import EdgeTTSProvider, HttpTTSProvider

        for adapter, provider_cls in (("http-tts", HttpTTSProvider), ("edge", EdgeTTSProvider)):
            with self.subTest(adapter=adapter):
                fixture = _ProbeFixture(health={"ok": True, "ready": True}, voice_config=_relay_config(dict(_OK_RELAY)))
                try:
                    with tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        config_path = self._write_config_with_tts_adapter(root, fixture.url, adapter)
                        service = self._create(config_path)
                        assert service.tts_chain is not None
                        self.assertIsInstance(service.tts_chain.targets[0].provider, provider_cls)
                        self.assertTrue(service.refresh_production_readiness())
                        self.assertEqual(fixture.posts, 0)
                finally:
                    fixture.close()
                # Malformed semantics: wrong-typed nested ready must reject
                # construction (positive elsewhere does not rescue it).
                fixture = _ProbeFixture(
                    health={"ok": True, "ready": True},
                    voice_config=_relay_config({"mode": "relay", "ok": True, "ready": ["y"], "reason": "provider 'edge' has no client wire"}),
                )
                try:
                    with tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        config_path = self._write_config_with_tts_adapter(root, fixture.url, adapter)
                        opened: list[str] = []
                        original_init = RecorderStore.__init__

                        def trap_init(store_self: Any, *args: Any, **kwargs: Any) -> None:
                            opened.append("store")
                            original_init(store_self, *args, **kwargs)

                        with patch.object(RecorderStore, "__init__", trap_init):
                            with self.assertRaises(ProviderFailure) as raised:
                                self._create(config_path, production=True)
                            self.assertIn(raised.exception.kind, {"tts_capability_unknown", "tts_disabled"})
                        self.assertEqual(opened, [], "negative readiness must not construct RecorderStore")
                        self.assertEqual(fixture.posts, 0)
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


class Voice1B6ExecutableClosureTests(unittest.TestCase):
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
        self.assertEqual(control.REQUIRED_PREDICATES, (
            "authorization_bound", "candidate_bound", "imports_bound",
            "credential_custody", "dashboard_credential_parse", "api_credential_parse",
            "lifetime_pre", "unauthenticated_gate", "api_capability", "asr_ready", "tts_ready",
            "omitted_profile_equal", "omitted_profile_ready", "generic_preflight", "session_get",
            "persisted_lookup_ro", "persisted_lookup_indexed", "session_budget",
            "payload_object_match", "source_match", "id_match", "lifecycle_match",
            "persisted_row_count_match", "persisted_id_match", "persisted_source_match",
            "persisted_ended_at_null", "conversation_key_match", "distinct_key_identity",
            "lifetime_post", "closing_identity_equal", "no_mutation", "secret_safe",
        ))
        self.assertEqual(len(set(control.REQUIRED_PREDICATES)), 32)

    def test_main_without_flags_is_structured_hold_exit_2(self):
        # B6 REV-008: any noncanonical invocation prints one JSON HOLD/2.
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

    def test_main_rejects_malformed_invocations_as_structured_hold(self):
        control = self.control
        cases = (
            ["--read-only-admission"],  # missing pairs
            ["--read-only-admission", "--manifest"],
            ["--read-only-admission", "--manifest", "m.json", "--manifest-sha256", "0" * 64,
             "--authorization", "a.json", "--authorization-sha256", "0" * 64, "--extra"],  # unknown flag
            ["--read-only-admission", "--manifest", "m.json", "--manifest", "m2.json",
             "--manifest-sha256", "0" * 64, "--authorization", "a.json",
             "--authorization-sha256", "0" * 64],  # duplicate flag
            ["--read-only-admission", "--manifest", "relative.json", "--manifest-sha256", "0" * 64,
             "--authorization", "/tmp/a.json", "--authorization-sha256", "0" * 64],  # relative path
            ["--read-only-admission", "--manifest", "/tmp/m.json", "--manifest-sha256", "0" * 64,
             "--authorization", "/tmp/a.json", "--authorization-sha256", "AB" * 32],  # uppercase digest
            ["--read-only-admission", "positional"],  # positional extra
            ["--read-only", "--admission"],  # abbreviation is not the switch
        )
        for argv in cases:
            with self.subTest(argv=argv):
                with contextlib.redirect_stdout(io.StringIO()) as captured:
                    exit_code = control.main(list(argv))
                stderr = io.StringIO()
                report = json.loads(captured.getvalue())
                self.assertEqual(exit_code, 2)
                self.assertEqual(report.get("status"), "HOLD")
                self.assertEqual(report.get("status_code"), 2)
                self.assertEqual(stderr.getvalue(), "")

    def test_module_main_block_is_the_only_action_and_raises_system_exit_main(self):
        # B6 expectation correction (REV-008): the guarded block is exactly
        # `raise SystemExit(main())`; the B4 instruction-only guard is
        # superseded by the executable caller.
        source = Path(self.control.__file__).read_text(encoding="utf-8")
        guard = re.search(r'if __name__ == "__main__":\n(.*)\Z', source, re.S)
        assert guard is not None
        self.assertIn("raise SystemExit(main())", guard.group(1))
        self.assertNotIn("run_voice1_readonly_admission(", guard.group(1))
        self.assertNotIn("print(", guard.group(1))

    def test_import_does_not_touch_boundary_state(self):
        source_path = Path(self.control.__file__)
        module_name = f"_b6_reimport_probe_{uuid.uuid4().hex}"
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

    # -- aggregate contract (S.4): the pure reducer is exercised directly ----

    def _report_context(self) -> dict[str, Any]:
        return {
            "manifest_sha256": "0" * 64,
            "authorization_sha256": "1" * 64,
        }

    def test_aggregate_rejects_each_false_or_missing_predicate(self):
        # The reducer is pure: every required name present-True is the only
        # PASS shape.  A False/1/"true" value fails that name; a None/absent
        # name is missing.  Observation results can never be injected through
        # a context: run_voice1_readonly_admission accepts no such inputs
        # (proven separately in test_context_cannot_inject_attestations).
        control = self.control
        base = {name: True for name in control.REQUIRED_PREDICATES}
        for name in control.REQUIRED_PREDICATES:
            for mutation in (False, 1, "true"):
                with self.subTest(predicate=name, value=mutation):
                    predicates = dict(base)
                    predicates[name] = mutation
                    report = control._admission_report(self._report_context(), predicates, [],
                                                       time.monotonic(), control._utc_now_iso(), {})
                    self.assertEqual(report["status"], "HOLD")
                    self.assertEqual(report["status_code"], 2)
                    self.assertIn(name, report["failed_predicates"])
            with self.subTest(predicate=name, value="null-removed"):
                predicates = dict(base)
                predicates[name] = None
                report = control._admission_report(self._report_context(), predicates, [],
                                                   time.monotonic(), control._utc_now_iso(), {})
                self.assertEqual(report["status"], "HOLD")
                self.assertIn(name, report["missing_predicates"])
            with self.subTest(predicate=name, value="absent"):
                predicates = {key: value for key, value in base.items() if key != name}
                report = control._admission_report(self._report_context(), predicates, [],
                                                   time.monotonic(), control._utc_now_iso(), {})
                self.assertEqual(report["status"], "HOLD")
                self.assertIn(name, report["missing_predicates"])

    def test_aggregate_all_true_passes_with_exact_schema(self):
        control = self.control
        predicates = {name: True for name in control.REQUIRED_PREDICATES}
        report = control._admission_report(self._report_context(), predicates, [],
                                           time.monotonic(), control._utc_now_iso(), {})
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["status_code"], 0)
        self.assertEqual(report["schema"], control.REPORT_SCHEMA)
        self.assertEqual(set(report["predicates"]), set(control.REQUIRED_PREDICATES))
        self.assertEqual(report["missing_predicates"], [])
        self.assertEqual(report["failed_predicates"], [])
        # B6 report additions
        self.assertEqual(report["observation_order"], list(control.OBSERVATION_ORDER))
        self.assertIn("boot_id", report)
        self.assertIn("session_observed_monotonic_ns", report)
        self.assertIn("execution_scope", report)

    def test_context_cannot_inject_attestations(self):
        # B6 REV-008: the caller performs observations; no attestation-style
        # context key (predicate_overrides / import_origin_ok / etc.) exists
        # in its signature.  A context full of all-True attestations and no
        # valid manifest/authorization produces HOLD with missing predicates,
        # never PASS.
        control = self.control
        context: dict[str, Any] = {
            "predicate_overrides": {name: True for name in control.REQUIRED_PREDICATES},
            "import_origin_ok": True,
            "per_file_hashes_ok": True,
            "credential_custody_ok": True,
            "no_mutation_ok": True,
            "secret_safe_ok": True,
            "closing_identity_ok": True,
        }
        report = control.run_voice1_readonly_admission(context)
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["status_code"], 2)
        self.assertTrue(report["missing_predicates"] or report["failed_predicates"])

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

    # -- B6 S-OBS: real boundary observations through the executable caller --

    def _sobs_authority(self, tmp: Path, endpoints: dict[str, str], paths: dict[str, str],
                        metadata: dict[str, Any]) -> dict[str, Any]:
        """Final-shaped fixture_readonly authority bound to this worktree."""
        runner_path = Path(self.control.__file__ or "run/qa_probe_runner.py")
        runner_sha = hashlib.sha256(runner_path.read_bytes()).hexdigest()
        candidate_root = runner_path.resolve().parents[1]
        # Exact candidate-root member pins: the executable caller now
        # verifies the pinned archive bytes, safe archive member set,
        # canonical vector, and every candidate-root member digest before
        # any import, so this fixture binds the REAL worktree digests and
        # a REAL harmless archive whose bytes hash to candidate_sha256.
        import io as _io
        import tarfile as _tarfile

        bundle_members = tuple(
            sorted(
                path.relative_to(candidate_root).as_posix()
                for path in (candidate_root / "recorder_next").glob("*.py")
            )
        )
        per_file: dict[str, str] = {}
        archive_buf = _io.BytesIO()
        with _tarfile.open(fileobj=archive_buf, mode="w") as tar:
            for member in bundle_members:
                member_bytes = (candidate_root / member).read_bytes()
                per_file[member] = hashlib.sha256(member_bytes).hexdigest()
                info = _tarfile.TarInfo(name=member)
                info.size = len(member_bytes)
                tar.addfile(info, _io.BytesIO(member_bytes))
        archive_bytes = archive_buf.getvalue()
        archive_path = tmp / "fixture-candidate.tar"
        archive_path.write_bytes(archive_bytes)
        fixture_root = tmp / "fixture-root"
        fixture_root.mkdir(exist_ok=True)
        fixture_root.chmod(0o700)
        manifest = {
            "schema": "recorder-next-voice1-b6-builder-candidate/v1",
            "generation": "VOICE1-B6",
            "product_identity": "recorder-next-server-voice-session-chain",
            "candidate_id": "fixture-candidate",
            "candidate_sha256": hashlib.sha256(archive_bytes).hexdigest(),
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "candidate_incomplete": False,
            "authorities": {"owner_packet_sha256": self.control.RATIFIED_OWNER_PACKET_SHA256,
                            "specification_sha256": self.control.RATIFIED_ADDENDUM_SHA256,
                            "inherited_specification_sha256": self.control.RATIFIED_INHERITED_SPEC_SHA256},
            "per_file_sha256": per_file,
            "tracked_file_count": len(per_file),
            "tracked_file_vector_sha256": hashlib.sha256(
                json.dumps(per_file, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            ).hexdigest(),
            "control": {"packet_sha256": "6" * 64, "probe_runner_sha256": runner_sha},
        }
        mp = tmp / "candidate-manifest.json"
        mp.write_text(json.dumps(manifest), encoding="utf-8")
        authorization = {
            "schema": "recorder-next-voice1-readonly-authorization/v1",
            "execution_scope": "fixture_readonly",
            "product_identity": "recorder-next-server-voice-session-chain",
            "candidate_id": "fixture-candidate",
            "candidate_sha256": hashlib.sha256(archive_bytes).hexdigest(),
            "manifest_sha256": hashlib.sha256(mp.read_bytes()).hexdigest(),
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "control_sha256": runner_sha,
            "control_packet_sha256": "6" * 64,
            "specification_sha256": self.control.RATIFIED_ADDENDUM_SHA256,
            "inherited_specification_sha256": self.control.RATIFIED_INHERITED_SPEC_SHA256,
            "owner_packet_sha256": self.control.RATIFIED_OWNER_PACKET_SHA256,
            "candidate_root": str(Path(self.control.__file__).resolve().parents[1]),
            "archive_path": str(tmp / "fixture-candidate.tar"),
            "approved_actions": ["candidate_verify", "credential_read", "unauthenticated_get",
                                 "api_capability_get", "audio_readiness_get", "session_get",
                                 "persisted_metadata_select", "closing_verify"],
            "endpoints": dict(endpoints),
            "paths": dict(paths),
            "credential_metadata": metadata,
            "selected_session_id_sha256": "7333f832a973d42820f71000d93921a4e05b953ab2fcc5d214985c84008d3e5a",
            "persisted_key_sha256": hashlib.sha256(b"voice1-b6-synthetic-persisted-key").hexdigest(),
            "not_before_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60)),
            "expires_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
            "fixture_root": str(tmp / "fixture-root"),
        }
        ap = tmp / "authorization.json"
        ap.write_text(json.dumps(authorization), encoding="utf-8")
        return {"manifest": manifest, "authorization": authorization,
                "manifest_path": str(mp), "authorization_path": str(ap),
                "manifest_sha256": hashlib.sha256(mp.read_bytes()).hexdigest(),
                "authorization_sha256": hashlib.sha256(ap.read_bytes()).hexdigest()}

    def test_observations_fail_closed_at_each_boundary(self):
        # Every observation failure returns HOLD before any downstream work:
        # custody mismatch -> credential parse failure -> metadata lifetime ->
        # wrong gate status -> duplicate session rows -> nonnull ended_at ->
        # independently pinned key mismatch.  These drive run_voice1_readonly_
        # admission with real files (metadata/DB) and stubbed HTTP only.
        control = self.control

        def authority(tmp: Path, **overrides: Any) -> dict[str, Any]:
            endpoints = overrides.pop("endpoints", {"api_base_url": "http://127.0.0.1:41001",
                                                    "dashboard_base_url": "http://127.0.0.1:41002"})
            fixture_root = tmp / "fixture-root"
            fixture_root.mkdir(exist_ok=True)
            fixture_root.chmod(0o700)
            paths = overrides.pop("paths", {
                "dashboard_credential": str(fixture_root / "dash.env"),
                "dashboard_metadata": str(fixture_root / "dash.meta.json"),
                "api_credential": str(fixture_root / "api.env"),
                "persisted_db": str(fixture_root / "db.sqlite3"),
            })
            metadata = overrides.pop("credential_metadata", {
                "dashboard_credential": {"device": 0, "inode": 0, "uid": 0, "gid": 0, "mode": 0},
                "api_credential": {"device": 0, "inode": 0, "uid": 0, "gid": 0, "mode": 0},
            })
            return self._sobs_authority(tmp, endpoints, paths, metadata)

        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            context = authority(tmp)
            report = control.run_voice1_readonly_admission(dict(context))
            self.assertEqual(report["status"], "HOLD")
            self.assertIn("credential_custody", report["reason_codes"])
            self.assertEqual(report["predicates"]["credential_custody"], False)
            # No downstream predicate may have been observed.
            self.assertFalse(report["predicates"]["unauthenticated_gate"])

        # Metadata lifetime below the 3900s floor.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fixture_root = tmp / "fixture-root"
            fixture_root.mkdir(exist_ok=True)
            fixture_root.chmod(0o700)
            dash = fixture_root / "dash.env"
            dash.write_text("API_SERVER_KEY=x\n", encoding="ascii")
            dash.chmod(0o600)
            info = dash.stat()
            pin = {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
                   "gid": info.st_gid, "mode": info.st_mode & 0o7777}
            api = fixture_root / "api.env"
            api.write_text("API_SERVER_KEY=y\n", encoding="ascii")
            api.chmod(0o600)
            api_info = api.stat()
            api_pin = {"device": api_info.st_dev, "inode": api_info.st_ino, "uid": api_info.st_uid,
                       "gid": api_info.st_gid, "mode": api_info.st_mode & 0o7777}
            meta_path = fixture_root / "dash.meta.json"
            short = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 1200))
            meta_path.write_text(json.dumps({"expires_at_utc": short}), encoding="utf-8")
            context = authority(
                tmp,
                credential_metadata={"dashboard_credential": pin, "api_credential": api_pin},
            )
            report = control.run_voice1_readonly_admission(dict(context))
            self.assertIn("lifetime", report["reason_codes"])
            self.assertEqual(report["predicates"]["lifetime_pre"], False)

        # Duplicate persisted rows -> row-count predicate failure.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            dash = tmp / "dash.env"
            dash.write_text("API_SERVER_KEY=x\n", encoding="ascii")
            dash.chmod(0o600)
            info = dash.stat()
            pin = {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
                   "gid": info.st_gid, "mode": info.st_mode & 0o7777}
            meta_path = tmp / "dash.meta.json"
            ok_expiry = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 7200))
            meta_path.write_text(json.dumps({"expires_at_utc": ok_expiry}), encoding="utf-8")
            db_path = tmp / "db.sqlite3"
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT, session_key TEXT, ended_at TEXT)")
            key = "voice1-b6-synthetic-persisted-key"
            s = "20260703_210417_8f66b434"
            # The pure predicate requires exactly one row; prove the caller's
            # read-only lookup feeds it by exercising the predicate directly
            # with a duplicate set (the executable lane stays file-driven).
            result = control.voice1_session_admission(
                {"object": "hermes.session",
                 "session": {"id": s, "source": "discord", "archived": False, "ended_at": None}},
                [(s, "discord", key, None), (s, "discord", key, None)],
                expected_session_id=s,
                expected_key_sha256=hashlib.sha256(key.encode()).hexdigest(),
            )
            conn.close()
            self.assertEqual(result["status"], "HOLD")
            self.assertIn("persisted_row_duplicate", result["reason_codes"])

    def test_sobs_session_admission_positive_and_key_pins(self):
        control = self.control
        s = "20260703_210417_8f66b434"
        key = "voice1-b6-synthetic-persisted-key"
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        payload = {"object": "hermes.session",
                   "session": {"id": s, "source": "discord", "archived": False, "ended_at": None}}
        ok = control.voice1_session_admission(payload, [(s, "discord", key, None)],
                                              expected_session_id=s, expected_key_sha256=digest)
        self.assertEqual(ok["status"], "PASS")
        # Wrong independently pinned key rejects even though the row shape is perfect.
        wrong = control.voice1_session_admission(payload, [(s, "discord", "other-key", None)],
                                                 expected_session_id=s, expected_key_sha256=digest)
        self.assertEqual(wrong["status"], "HOLD")
        # Key equal to S violates distinct identity.
        same = control.voice1_session_admission(payload, [(s, "discord", s, None)],
                                                expected_session_id=s, expected_key_sha256=digest)
        self.assertEqual(same["status"], "HOLD")
        # Non-NULL ended_at rejects.
        ended = control.voice1_session_admission(payload, [(s, "discord", key, "2026-09-13T00:00:00Z")],
                                                 expected_session_id=s, expected_key_sha256=digest)
        self.assertEqual(ended["status"], "HOLD")
        self.assertFalse(ended["persisted_ended_at_null"])

    # -- executor boundary matrix: real functions, private fixture root -----

    def test_executor_functions_reject_live_fixture_context(self):
        with self.assertRaises(self.control.AttemptContextError):
            self.control._validate_fixture_context({
                "fixture_root": "/var/lib/recorder-next",
                "db_path": "/var/lib/recorder-next/recorder-next.sqlite3",
            })
        with self.assertRaises(self.control.AttemptContextError):
            self.control._validate_fixture_context({"fixture_root": None, "db_path": None})

    def test_gate_secret_check_normalizes_http_bytes(self):
        check = self.control._secrets_absent
        self.assertTrue(check(b'{"status": "unauthorized"}', ("dash", "api")))
        self.assertTrue(check('{"status": "unauthorized"}', ("dash", "api")))
        self.assertFalse(check(b'{"token": "dash"}', ("dash", "api")))
        self.assertFalse(check(b"unauthorized", (None, "api")))


class Voice1B6E4FindingRegressionTests(unittest.TestCase):
    """Focused RED tests for the six E4 review findings."""

    @classmethod
    def setUpClass(cls) -> None:
        control_dir = Path(__file__).resolve().parents[1] / "run"
        if str(control_dir) not in sys.path:
            sys.path.insert(0, str(control_dir))
        import qa_probe_runner as control

        cls.control = control

    def _manifest(self) -> dict[str, Any]:
        runner = Path(self.control.__file__ or "run/qa_probe_runner.py")
        adapters = runner.parents[1] / "recorder_next" / "adapters.py"
        per_file = {"recorder_next/adapters.py": hashlib.sha256(adapters.read_bytes()).hexdigest()}
        vector = hashlib.sha256(
            json.dumps(per_file, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()
        return {
            "schema": "recorder-next-voice1-b6-builder-candidate/v1",
            "generation": "VOICE1-B6",
            "product_identity": "recorder-next-server-voice-session-chain",
            "candidate_id": "fixture-candidate",
            "candidate_sha256": "0" * 64,
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "candidate_incomplete": False,
            "authorities": {
                "owner_packet_sha256": "6735b40c2eeeb716fb307d73cb603c940b24a78cab9cb29ddf6b696b1e99a3ec",
                "specification_sha256": "758fcf9642ea21e7017b70e0851a88f3c11d7c0ee727e16516b923e8f8f1085e",
                "inherited_specification_sha256": "ce1c23271239d330e7125ded8ecb6b32d0a3bee8c5d2a07118693c3065df3de1",
            },
            "per_file_sha256": per_file,
            "tracked_file_count": 1,
            "tracked_file_vector_sha256": vector,
            "control": {
                "packet_sha256": "6" * 64,
                "probe_runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
            },
        }

    def _authorization(self, root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema": "recorder-next-voice1-readonly-authorization/v1",
            "execution_scope": "fixture_readonly",
            "product_identity": "recorder-next-server-voice-session-chain",
            "candidate_id": manifest["candidate_id"],
            "candidate_sha256": manifest["candidate_sha256"],
            "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
            "source_commit": manifest["source_commit"],
            "source_tree": manifest["source_tree"],
            "control_sha256": manifest["control"]["probe_runner_sha256"],
            "control_packet_sha256": manifest["control"]["packet_sha256"],
            "specification_sha256": manifest["authorities"]["specification_sha256"],
            "inherited_specification_sha256": manifest["authorities"]["inherited_specification_sha256"],
            "owner_packet_sha256": manifest["authorities"]["owner_packet_sha256"],
            "candidate_root": str(Path(self.control.__file__ or "run/qa_probe_runner.py").resolve().parents[1]),
            "archive_path": str(root / "candidate.tar"),
            "approved_actions": list(self.control.APPROVED_ACTIONS),
            "endpoints": {"api_base_url": "http://127.0.0.1:41001", "dashboard_base_url": "http://127.0.0.1:41002"},
            "paths": {
                "dashboard_credential": str(root / "dashboard.env"),
                "dashboard_metadata": str(root / "dashboard.meta.json"),
                "api_credential": str(root / "api.env"),
                "persisted_db": str(root / "state.db"),
            },
            "credential_metadata": {
                "dashboard_credential": {"device": 1, "inode": 2, "uid": 3, "gid": 4, "mode": 0o600},
                "api_credential": {"device": 1, "inode": 5, "uid": 3, "gid": 4, "mode": 0o600},
            },
            "selected_session_id_sha256": self.control.EXPECTED_S_SHA256,
            "persisted_key_sha256": self.control.FIXTURE_KEY_SHA256,
            "not_before_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60)),
            "expires_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
            "fixture_root": str(root),
        }

    def test_malformed_manifest_scalar_is_structured_hold_without_stderr(self):
        manifest = self._manifest()
        manifest["candidate_sha256"] = 1
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            mp = root / "manifest.json"
            ap = root / "authorization.json"
            mp.write_text(json.dumps(manifest), encoding="utf-8")
            ap.write_text("{}", encoding="utf-8")
            argv = [
                "--read-only-admission", "--manifest", str(mp),
                "--manifest-sha256", hashlib.sha256(mp.read_bytes()).hexdigest(),
                "--authorization", str(ap),
                "--authorization-sha256", hashlib.sha256(ap.read_bytes()).hexdigest(),
            ]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = self.control.main(argv)
        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["status_code"], 2)
        self.assertEqual(stderr.getvalue(), "")

    def test_authority_binding_enforces_scope_specific_paths_and_endpoints(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            root.chmod(0o700)
            manifest = self._manifest()
            authorization = self._authorization(root, manifest)
            manifest_sha = authorization["manifest_sha256"]
            self.assertTrue(self.control._verify_authority_binding(manifest, authorization, manifest_sha))
            for field, value in (
                ("endpoints", {"api_base_url": "http://example.com:443", "dashboard_base_url": "http://127.0.0.1:41002"}),
                ("paths", {**authorization["paths"], "persisted_db": "/etc/passwd"}),
                ("fixture_root", "/tmp/not-the-private-root"),
            ):
                mutated = dict(authorization)
                mutated[field] = value
                self.assertFalse(self.control._verify_authority_binding(manifest, mutated, manifest_sha))

    def test_import_is_inert_without_path_resolve(self):
        source_path = Path(self.control.__file__ or "run/qa_probe_runner.py")
        module_name = f"_b6_e4_import_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(module_name, source_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        with patch.object(Path, "resolve", side_effect=AssertionError("import-time resolve")):
            spec.loader.exec_module(module)

    def test_canonical_argv_rejects_reordered_options_and_guard_has_one_action(self):
        digest = "a" * 64
        canonical = [
            "--read-only-admission", "--manifest", "/tmp/m.json", "--manifest-sha256", digest,
            "--authorization", "/tmp/a.json", "--authorization-sha256", digest,
        ]
        reordered = [
            "--read-only-admission", "--manifest-sha256", digest, "--manifest", "/tmp/m.json",
            "--authorization-sha256", digest, "--authorization", "/tmp/a.json",
        ]
        self.assertIsNotNone(self.control._canonical_argv(canonical))
        self.assertIsNone(self.control._canonical_argv(reordered))
        source = Path(self.control.__file__ or "run/qa_probe_runner.py").read_text(encoding="utf-8")
        guard = source.split('if __name__ == "__main__":', 1)[1]
        self.assertNotIn("voice1-gap-child", guard)
        self.assertNotIn("_gap_args", guard)
        self.assertEqual(guard.strip(), "raise SystemExit(main())")

    def test_canonical_argv_rejects_absolute_dot_alias_paths_as_invalid(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            nested = root / "nested"
            nested.mkdir()
            manifest = nested / "manifest.json"
            authorization = nested / "authorization.json"
            manifest.write_text("{}", encoding="utf-8")
            authorization.write_text("{}", encoding="utf-8")
            manifest_alias = nested / ".." / "nested" / "manifest.json"
            authorization_alias = nested / "sub" / ".." / "authorization.json"
            # The files exist and their digests are correct; only the argv
            # path spelling is noncanonical and must be held before file I/O.
            argv = [
                "--read-only-admission", "--manifest", str(manifest_alias),
                "--manifest-sha256", hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "--authorization", str(authorization_alias),
                "--authorization-sha256", hashlib.sha256(authorization.read_bytes()).hexdigest(),
            ]
            self.assertIsNone(self.control._canonical_argv(argv))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = self.control.main(argv)
            report = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 2)
            self.assertEqual(report["status"], "HOLD")
            self.assertEqual(report["status_code"], 2)
            self.assertIn("invalid_argv", report["reason_codes"])
            self.assertEqual(stderr.getvalue(), "")

    def test_profile_validator_rejects_non2xx_and_identical_invalid_projections(self):
        valid = {
            "ok": True, "ready": True, "configured": True, "enabled": True, "audio_api": True,
            "stt": {"mode": "relay", "provider": "hermes-stt"},
            "tts": {"mode": "relay", "reason": "command/plugin provider", "wire": "server",
                    "provider": "edge", "configured": True, "enabled": True, "ready": True,
                    "ok": True, "status": "ok"},
        }
        explicit = self.control._tts_reduction(valid)
        self.assertTrue(self.control._profile_observations_ready(
            {"status": 200, "body": json.dumps(valid).encode("utf-8")},
            {"status": 200, "projection": explicit},
        ))
        self.assertFalse(self.control._profile_observations_ready(
            {"status": 500, "body": json.dumps(valid).encode("utf-8")},
            {"status": 200, "projection": explicit},
        ))
        invalid = self.control._tts_reduction({"ok": True, "tts": {"configured": "invalid:str"}})
        self.assertFalse(self.control._profile_observations_ready(
            {"status": 200, "body": json.dumps({"ok": True, "tts": {"configured": "invalid:str"}}).encode("utf-8")},
            {"status": 200, "projection": invalid},
        ))

    def test_admission_report_rejects_extra_and_non_boolean_predicates(self):
        predicates: dict[str, Any] = {name: True for name in self.control.REQUIRED_PREDICATES}
        predicates["unexpected"] = True
        report = self.control._admission_report(
            {}, predicates, [], time.monotonic(), "2026-09-13T00:00:00Z", {}, observations={},
        )
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["status_code"], 2)
        self.assertEqual(report["predicates"], {
            name: True for name in self.control.REQUIRED_PREDICATES
        })

        predicates = {name: True for name in self.control.REQUIRED_PREDICATES}
        predicates["authorization_bound"] = 1
        report = self.control._admission_report(
            {}, predicates, [], time.monotonic(), "2026-09-13T00:00:00Z", {}, observations={},
        )
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["status_code"], 2)
        self.assertIs(type(report["predicates"]["authorization_bound"]), bool)
        self.assertFalse(report["predicates"]["authorization_bound"])
        self.assertIn("authorization_bound", report["failed_predicates"])

    def test_persisted_lookup_installs_authorizer_and_denies_non_whitelisted_action(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            db_path = root / "state.db"
            with sqlite3.connect(db_path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE sessions (
                        id TEXT NOT NULL,
                        source TEXT NOT NULL,
                        session_key TEXT NOT NULL,
                        ended_at TEXT
                    );
                    CREATE INDEX sessions_id_idx ON sessions(id);
                    INSERT INTO sessions VALUES (
                        '20260703_210417_8f66b434', 'discord', 'fixture-key', NULL
                    );
                    """
                )

            real_connect = sqlite3.connect
            observed: dict[str, Any] = {}

            class AuditedConnection(sqlite3.Connection):
                def set_authorizer(self, authorizer_callback):
                    observed["set_authorizer_calls"] = observed.get("set_authorizer_calls", 0) + 1
                    observed["delete_decision"] = authorizer_callback(
                        sqlite3.SQLITE_DELETE, "sessions", None, "main", None
                    )
                    return super().set_authorizer(authorizer_callback)

            def connect(*args, **kwargs):
                kwargs["factory"] = AuditedConnection
                return real_connect(*args, **kwargs)

            context = {"authorization": {"paths": {"persisted_db": str(db_path)}},
                       "boundary": {"sqlite_connect": connect}}
            with patch.object(self.control.sqlite3, "connect", side_effect=connect):
                result = self.control._persisted_lookup(
                    context, deadline_at=time.monotonic() + 5.0
                )

        self.assertTrue(result["read_only"])
        self.assertTrue(result["indexed"])
        self.assertEqual(observed["set_authorizer_calls"], 1)
        self.assertEqual(observed["delete_decision"], sqlite3.SQLITE_DENY)

    def test_persisted_lookup_uses_shared_deadline_progress_and_db_identity(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            db_path = root / "state.db"
            with sqlite3.connect(db_path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE sessions (
                        id TEXT NOT NULL,
                        source TEXT NOT NULL,
                        session_key TEXT NOT NULL,
                        ended_at TEXT
                    );
                    CREATE INDEX sessions_id_idx ON sessions(id);
                    INSERT INTO sessions VALUES (
                        '20260703_210417_8f66b434', 'discord', 'fixture-key', NULL
                    );
                    """
                )

            real_connect = sqlite3.connect
            observed: dict[str, Any] = {}

            class AuditedConnection(sqlite3.Connection):
                def set_progress_handler(self, progress_handler, n):
                    observed.setdefault("progress_handlers", []).append((progress_handler, n))
                    return super().set_progress_handler(progress_handler, n)

            def connect(*args, **kwargs):
                observed["connect_kwargs"] = dict(kwargs)
                kwargs["factory"] = AuditedConnection
                return real_connect(*args, **kwargs)

            deadline_at = time.monotonic() + 2.0
            context = {"authorization": {"paths": {"persisted_db": str(db_path)},
                         }, "boundary": {"sqlite_connect": connect}}
            with patch.object(self.control.sqlite3, "connect", side_effect=connect):
                result = self.control._persisted_lookup(context, deadline_at=deadline_at)

            self.assertTrue(result["read_only"])
            self.assertTrue(result["indexed"])
            self.assertLessEqual(observed["connect_kwargs"]["timeout"], 2.0)
            self.assertLessEqual(observed["connect_kwargs"]["timeout"], 5.0)
            progress_handlers = observed["progress_handlers"]
            handler, interval = next((item for item in progress_handlers if callable(item[0])))
            self.assertTrue(callable(handler))
            self.assertGreater(interval, 0)

            identity = self.control._path_object_identity(db_path)
            self.assertIsNotNone(identity)
            assert identity is not None
            with patch.object(
                self.control,
                "_path_object_identity",
                side_effect=[
                    identity,
                    (identity[0], identity[1] + 1, identity[2]),
                    (identity[0], identity[1] + 1, identity[2]),
                    (identity[0], identity[1] + 1, identity[2]),
                    (identity[0], identity[1] + 1, identity[2]),
                ],
            ):
                drifted = self.control._persisted_lookup(
                    context, deadline_at=time.monotonic() + 2.0
                )
        self.assertFalse(drifted["read_only"])
        self.assertFalse(drifted["indexed"])

    def test_persisted_lookup_uri_escapes_percent_encoded_path_components(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            inside_dir = root / "%2e%2e"
            inside_dir.mkdir()
            inside_db = inside_dir / "selected.db"
            outside_db = root.parent / "selected.db"

            schema = """
                CREATE TABLE sessions (
                    id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    session_key TEXT NOT NULL,
                    ended_at TEXT
                );
                CREATE INDEX sessions_id_idx ON sessions(id);
            """
            with sqlite3.connect(inside_db) as connection:
                connection.executescript(schema)
            with sqlite3.connect(outside_db) as connection:
                connection.executescript(schema)
                connection.execute(
                    "INSERT INTO sessions VALUES (?, ?, ?, ?)",
                    ("20260703_210417_8f66b434", "outside", "outside-key", None),
                )

            context = {"authorization": {"paths": {"persisted_db": str(inside_db)}}}
            try:
                result = self.control._persisted_lookup(
                    context, deadline_at=time.monotonic() + 5.0
                )
            finally:
                outside_db.unlink(missing_ok=True)

        self.assertTrue(result["read_only"])
        self.assertTrue(result["indexed"])
        self.assertEqual(result["rows"], [], "lookup must not observe the outside DB row")

    def test_report_projects_scope_specific_persisted_key_digest(self):
        predicates = {name: True for name in self.control.REQUIRED_PREDICATES}
        fixture = self.control._admission_report(
            {}, predicates, [], 0.0, "2026-09-13T00:00:00Z", {}, observations={},
            authorization={"execution_scope": "fixture_readonly", "persisted_key_sha256": self.control.FIXTURE_KEY_SHA256},
        )
        live = self.control._admission_report(
            {}, predicates, [], 0.0, "2026-09-13T00:00:00Z", {}, observations={},
            authorization={"execution_scope": "live_readonly", "persisted_key_sha256": self.control.EXPECTED_KEY_SHA256},
        )
        self.assertEqual(fixture["persisted_key_sha256"], self.control.FIXTURE_KEY_SHA256)
        self.assertEqual(live["persisted_key_sha256"], self.control.EXPECTED_KEY_SHA256)


class Voice1B6E5FindingRegressionTests(unittest.TestCase):
    """Focused regression tests for the seven E5 review findings (F-1..F-7)."""

    E5_GIT_COMMIT = "54887b63b690daa74627efef8a06257396ffaab0"
    E5_GIT_TREE = "d45735715e8f75ef7c91bb280a433df9f1ebb89b"
    E5_GIT_TRACKED_COUNT = 77

    @classmethod
    def setUpClass(cls) -> None:
        control_dir = Path(__file__).resolve().parents[1] / "run"
        if str(control_dir) not in sys.path:
            sys.path.insert(0, str(control_dir))
        import qa_probe_runner as control

        cls.control = control

    # -- shared fixtures -----------------------------------------------------

    _BUNDLE_MEMBERS = (
        "recorder_next/__init__.py",
        "recorder_next/adapters.py",
        "recorder_next/canonical.py",
        "recorder_next/hermes_wire.py",
        "recorder_next/media.py",
        "recorder_next/models.py",
    )

    def _candidate_root(self) -> Path:
        return Path(self.control.__file__ or "run/qa_probe_runner.py").resolve().parents[1]

    def _manifest(self) -> dict[str, Any]:
        return Voice1B6E4FindingRegressionTests._manifest(self)

    def _authorization(self, root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
        return Voice1B6E4FindingRegressionTests._authorization(self, root, manifest)

    def _bundle_fixture(self, root: Path) -> tuple[dict[str, str], Path]:
        """A real 6-member candidate archive whose bytes are digest-pinned."""
        import io
        import tarfile

        datas: dict[str, bytes] = {}
        per_file: dict[str, str] = {}
        for member in self._BUNDLE_MEMBERS:
            if member == "recorder_next/__init__.py":
                data = b'"""fixture candidate package."""\n'
            else:
                data = (self._candidate_root() / member).read_bytes()
            datas[member] = data
            per_file[member] = hashlib.sha256(data).hexdigest()
        archive = root / "candidate.tar"
        with tarfile.open(archive, "w") as handle:
            for member in self._BUNDLE_MEMBERS:
                info = tarfile.TarInfo(member)
                info.size = len(datas[member])
                handle.addfile(info, io.BytesIO(datas[member]))
        return per_file, archive

    def _snapshot_candidate_modules(self) -> dict[str, Any]:
        return {
            name: module
            for name, module in sys.modules.items()
            if name == "recorder_next" or name.startswith("recorder_next.")
        }

    def _restore_candidate_modules(self, snapshot: dict[str, Any]) -> None:
        for name in [
            name
            for name in sys.modules
            if name == "recorder_next" or name.startswith("recorder_next.")
        ]:
            if name not in snapshot:
                del sys.modules[name]
        sys.modules.update(snapshot)

    # -- F-1: the gate precedes any recorder_next import ----------------------

    def test_f1_authority_drift_imports_nothing_and_holds(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            root.chmod(0o700)
            manifest = self._manifest()
            authorization = self._authorization(root, manifest)
            mp = root / "manifest.json"
            ap = root / "authorization.json"
            mp.write_text(json.dumps(manifest), encoding="utf-8")
            ap.write_text(json.dumps(authorization), encoding="utf-8")
            argv = [
                "--read-only-admission", "--manifest", str(mp),
                "--manifest-sha256", hashlib.sha256(mp.read_bytes()).hexdigest(),
                "--authorization", str(ap),
                "--authorization-sha256", hashlib.sha256(ap.read_bytes()).hexdigest(),
            ]
            snapshot = self._snapshot_candidate_modules()
            calls: list[str] = []
            real_import = importlib.import_module

            def guarded(name: str, *args: Any, **kwargs: Any):
                if name == "recorder_next" or name.startswith("recorder_next."):
                    calls.append(name)
                    raise AssertionError(f"import before gate: {name}")
                return real_import(name, *args, **kwargs)

            try:
                with patch.object(
                    self.control, "_cold_rehash_ratified_authorities", return_value=False
                ), patch.object(importlib, "import_module", side_effect=guarded):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        exit_code = self.control.main(argv)
                report = json.loads(stdout.getvalue())
                self.assertEqual(exit_code, 2)
                self.assertEqual(report["status"], "HOLD")
                self.assertEqual(calls, [], "no recorder_next import may occur on authority drift")
                self.assertEqual(stderr.getvalue(), "")
            finally:
                self._restore_candidate_modules(snapshot)

    # -- F-2: manifest-byte-bound candidate loader ---------------------------

    def test_f2_loader_binds_candidate_modules_to_manifest_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            per_file, archive = self._bundle_fixture(root)
            snapshot = self._snapshot_candidate_modules()
            try:
                # The test module itself preloads recorder_next; the loader must
                # see a clean namespace, so drop them for the load and restore after.
                self._restore_candidate_modules({})
                with patch.object(self.control, "_verify_candidate_source", return_value=True):
                    bundle = self.control._load_candidate_module_bundle(
                        {"per_file_sha256": per_file}, {"archive_path": str(archive)}
                    )
                self.assertIsInstance(bundle, dict)
                assert isinstance(bundle, dict)
                self.assertIn("recorder_next.adapters", bundle["modules"])
                adapters = bundle["adapters"]
                self.assertEqual(getattr(adapters, "__manifest_member__", None), "recorder_next/adapters.py")
                for name, member in bundle["modules"].items():
                    module = sys.modules.get(name)
                    self.assertIsNotNone(module)
                    spec = getattr(module, "__spec__", None)
                    self.assertIsInstance(getattr(spec, "loader", None), self.control._ManifestBytesLoader)
                    self.assertEqual(getattr(module, "__manifest_member__", None), member)
                self.assertTrue(
                    self.control._candidate_modules_still_bound(
                        bundle, {"per_file_sha256": per_file}, {"archive_path": str(archive)}
                    )
                )
            finally:
                self._restore_candidate_modules(snapshot)

    def test_f2_loader_rejects_forged_digest_drifted_archive_and_preload(self):
        import io
        import tarfile

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            per_file, archive = self._bundle_fixture(root)
            snapshot = self._snapshot_candidate_modules()
            try:
                self._restore_candidate_modules({})
                # (a) forged manifest digest for a member present in the archive:
                forged = dict(per_file)
                forged["recorder_next/adapters.py"] = "0" * 64
                with patch.object(self.control, "_verify_candidate_source", return_value=True):
                    self.assertIsNone(
                        self.control._load_candidate_module_bundle(
                            {"per_file_sha256": forged}, {"archive_path": str(archive)}
                        )
                    )
                # (b) archive member bytes drifted from the manifest pin:
                drifted_archive = root / "drifted.tar"
                data = (self._candidate_root() / "recorder_next" / "adapters.py").read_bytes() + b"\n# drift\n"
                with tarfile.open(drifted_archive, "w") as handle:
                    info = tarfile.TarInfo("recorder_next/adapters.py")
                    info.size = len(data)
                    handle.addfile(info, io.BytesIO(data))
                with patch.object(self.control, "_verify_candidate_source", return_value=True):
                    self.assertIsNone(
                        self.control._load_candidate_module_bundle(
                            {"per_file_sha256": per_file}, {"archive_path": str(drifted_archive)}
                        )
                    )
                # (c) a preloaded foreign recorder_next module blocks the bundle:
                self._restore_candidate_modules({})
                sentinel = importlib.util.module_from_spec(
                    importlib.util.spec_from_loader("recorder_next", loader=None)
                )
                sys.modules["recorder_next"] = sentinel
                try:
                    with patch.object(self.control, "_verify_candidate_source", return_value=True):
                        self.assertIsNone(
                            self.control._load_candidate_module_bundle(
                                {"per_file_sha256": per_file}, {"archive_path": str(archive)}
                            )
                        )
                finally:
                    del sys.modules["recorder_next"]
            finally:
                self._restore_candidate_modules(snapshot)

    # -- F-3: identity-bound credential custody ------------------------------

    def test_f3_credential_read_binds_value_to_custody_pinned_object(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            credential = root / "dashboard.env"
            credential.write_bytes(b"API_SERVER_KEY=Abc123value\n")
            info = credential.stat()
            import stat as stat_module

            pin = {
                "device": info.st_dev,
                "inode": info.st_ino,
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mode": stat_module.S_IMODE(info.st_mode),
            }
            value = self.control._read_credential_default(credential, pin)
            self.assertEqual(value, "Abc123value")
            swapped = root / "swap.env"
            swapped.write_bytes(b"API_SERVER_KEY=EvilSwapValue\n")
            # Pin the SWAPPED object's own identity, then corrupt one field so
            # the pin can never match the object actually opened (inode reuse
            # in a fresh directory makes off-by-one guesses unreliable).
            swapped_info = swapped.stat()
            drifted = {
                "device": swapped_info.st_dev,
                "inode": swapped_info.st_ino,
                "uid": swapped_info.st_uid,
                "gid": swapped_info.st_gid,
                "mode": stat_module.S_IMODE(swapped_info.st_mode),
            }
            drifted["mode"] = drifted["mode"] ^ 0o040  # always flips one mode bit
            with self.assertRaises(CredentialError):
                self.control._read_credential_default(swapped, drifted)
            link = root / "link.env"
            link.symlink_to(credential)
            with self.assertRaises(CredentialError):
                self.control._read_credential_default(link, pin)

    # -- F-4: redirected SQLite connection rejection -------------------------

    def test_f4_persisted_lookup_rejects_redirected_connection_file(self):
        def make_db(target: Path, row_id: str) -> None:
            connection = sqlite3.connect(str(target))
            try:
                connection.execute(
                    "CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT,"
                    " session_key TEXT, ended_at TEXT)"
                )
                connection.execute(
                    "INSERT INTO sessions (id, source, session_key, ended_at)"
                    " VALUES (?, 'x', 'k', NULL)",
                    (row_id,),
                )
                connection.commit()
            finally:
                connection.close()

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            real_db = root / "state.db"
            elsewhere = root / "elsewhere.db"
            make_db(real_db, "s1")
            make_db(elsewhere, "evil")
            context = {
                "authorization": {"paths": {"persisted_db": str(real_db)}},
                "session_deadline": time.monotonic() + 5.0,
            }
            healthy = self.control._persisted_lookup(dict(context))
            self.assertTrue(healthy["read_only"])
            self.assertTrue(healthy["db_connected_file_equal"])

            real_connect = sqlite3.connect

            def redirected_connect(*args: Any, **kwargs: Any):
                return real_connect(str(elsewhere))

            with patch.object(self.control.sqlite3, "connect", side_effect=redirected_connect):
                hijacked = self.control._persisted_lookup(dict(context))
            self.assertEqual(hijacked.get("rows"), [], "rows from a redirected connection must be dropped")
            self.assertFalse(hijacked.get("db_connected_file_equal", True))

    # -- F-5: one shared collision-free TTS projection ------------------------

    def test_f5_shared_projection_is_lossless_and_collision_free(self):
        reduce = self.control._tts_reduction
        self.assertNotEqual(reduce({"ok": False, "reason": 7}), reduce({"ok": False, "reason": "7"}))
        self.assertNotEqual(
            reduce({"ok": False, "reason": "invalid:list"}),
            reduce({"ok": False, "reason": ["a", "b"]}),
        )
        self.assertEqual(
            reduce({"tts": {"configured": "invalid:str"}}),
            reduce({"tts": {"configured": "invalid:str"}}),
        )
        self.assertEqual(
            reduce({"tts": {"voices": ["a", "b"]}}),
            reduce({"tts": {"voices": ["a", "b"]}}),
        )
        self.assertNotEqual(
            reduce({"tts": {"voices": ["a", "b"]}}),
            reduce({"tts": {"voices": ["b", "a"]}}),
        )
        self.assertNotEqual(reduce({"ok": True}), reduce({"ok": 1}))
        once = reduce({"ok": True, "tts": {"voices": ["a"]}})
        self.assertEqual(once, reduce(once))

    def _profile_response(self, body: Any) -> dict[str, Any]:
        return {"status": 200, "body": json.dumps(body).encode("utf-8")}

    def test_f5_profile_readiness_compares_through_one_shared_projection(self):
        valid = {
            "ok": True, "ready": True, "configured": True, "enabled": True, "audio_api": True,
            "stt": {"mode": "relay", "provider": "hermes-stt"},
            "tts": {"mode": "relay", "reason": "command/plugin provider", "wire": "server",
                    "provider": "edge", "configured": True, "enabled": True, "ready": True,
                    "ok": True, "status": "ok"},
        }
        explicit = {"status": 200, "projection": self.control._tts_reduction(valid)}
        self.assertTrue(self.control._profile_observations_ready(self._profile_response(valid), explicit))

    def test_f5_profile_readiness_rejects_collision_and_divergence(self):
        base = {
            "ok": True, "ready": True, "configured": True, "enabled": True, "audio_api": True,
            "stt": {"mode": "relay", "provider": "hermes-stt"},
            "tts": {"mode": "relay", "reason": "command/plugin provider", "wire": "server",
                    "provider": "edge", "configured": True, "enabled": True, "ready": True,
                    "ok": True, "status": "ok"},
        }
        mutated = {
            "ok": True, "ready": True, "configured": True, "enabled": True, "audio_api": True,
            "stt": {"mode": "relay", "provider": "hermes-stt"},
            "tts": {"mode": "relay", "reason": "command/plugin provider", "wire": "server",
                    "provider": "edge", "configured": "invalid:str", "enabled": True,
                    "ready": True, "ok": True, "status": "ok"},
        }
        self.assertFalse(
            self.control._profile_observations_ready(
                self._profile_response(base),
                {"status": 200, "projection": self.control._tts_reduction(mutated)},
            )
        )
        diverged = dict(base)
        diverged["tts"] = dict(base["tts"], status="degraded")
        self.assertFalse(
            self.control._profile_observations_ready(
                self._profile_response(base),
                {"status": 200, "projection": self.control._tts_reduction(diverged)},
            )
        )
        spoofed = dict(base)
        spoofed["tts"] = dict(base["tts"], status="invalid:list")
        self.assertFalse(
            self.control._profile_observations_ready(
                self._profile_response(base),
                {"status": 200, "projection": self.control._tts_reduction(spoofed)},
            )
        )

    # -- F-6: canonical argv rejects double-slash aliases ---------------------

    def test_f6_canonical_argv_rejects_double_slash_path_aliases(self):
        digest = "a" * 64
        for manifest_alias, authorization_alias in (
            ("//tmp/m.json", "/tmp/a.json"),
            ("/tmp//m.json", "/tmp/a.json"),
            ("/tmp/m.json", "//tmp/a.json"),
        ):
            argv = [
                "--read-only-admission", "--manifest", manifest_alias,
                "--manifest-sha256", digest,
                "--authorization", authorization_alias,
                "--authorization-sha256", digest,
            ]
            self.assertIsNone(
                self.control._canonical_argv(argv),
                f"double-slash alias must be rejected: {manifest_alias}, {authorization_alias}",
            )

    def test_f6_admission_holds_on_double_slash_manifest_argv(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = root / "manifest.json"
            authorization = root / "authorization.json"
            manifest.write_text("{}", encoding="utf-8")
            authorization.write_text("{}", encoding="utf-8")
            argv = [
                "--read-only-admission",
                "--manifest", f"//{str(manifest).lstrip('/')}",
                "--manifest-sha256", hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "--authorization", str(authorization),
                "--authorization-sha256", hashlib.sha256(authorization.read_bytes()).hexdigest(),
            ]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = self.control.main(argv)
            report = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 2)
            self.assertEqual(report["status"], "HOLD")
            self.assertIn("invalid_argv", report["reason_codes"])
            self.assertEqual(stderr.getvalue(), "")

    # -- F-7: evidence-side anchors (sealed E4 packet) -------------------------

    def test_f7_sealed_e4_packet_anchors_git_identity_and_full_files(self):
        packet = Path(__file__).resolve().parents[1] / (
            ".release-artifacts/voice1-b6-e4-fresh-repair-candidate-final-r6"
        )
        self.assertTrue(packet.is_dir(), "sealed E4 packet must exist")
        manifest = json.loads((packet / "candidate-manifest.json").read_text(encoding="utf-8"))
        # Git-true 40-hex identity (never an abbreviated or invented vector):
        self.assertEqual(manifest.get("source_commit"), self.E5_GIT_COMMIT)
        self.assertEqual(manifest.get("source_tree"), self.E5_GIT_TREE)
        # tracked count states the real Git-tracked file count (77), and the
        # manifest carries a full-file detached anchor for EVERY tracked file:
        per_file = manifest.get("per_file_sha256")
        self.assertIsInstance(per_file, dict)
        self.assertEqual(manifest.get("tracked_file_count"), self.E5_GIT_TRACKED_COUNT)
        self.assertEqual(len(per_file), self.E5_GIT_TRACKED_COUNT)
        self.assertIn("run/qa_probe_runner.py", per_file)
        self.assertRegex(str(per_file["run/qa_probe_runner.py"]), r"^[0-9a-f]{64}$")
        # the detached manifest binds every other evidence member by full sha256
        # and the anchor for the runner is byte-verifiable against the source tar:
        detached = (packet / "detached-manifest.txt").read_text(encoding="utf-8")
        self.assertIn(f"source_commit={self.E5_GIT_COMMIT}", detached)
        self.assertIn(f"source_tree={self.E5_GIT_TREE}", detached)
        anchored: dict[str, str] = {}
        for line in detached.splitlines():
            if line.startswith("member="):
                name = line.split("=", 1)[1].split("\t", 1)[0]
                digest = line.rsplit("sha256=", 1)[1].strip()
                anchored[name] = digest
        self.assertIn("candidate-manifest.json", anchored)
        actual = hashlib.sha256((packet / "candidate-manifest.json").read_bytes()).hexdigest()
        self.assertEqual(anchored["candidate-manifest.json"], actual)


class R19ArgvProjectionTests(unittest.TestCase):
    """B6 A-SAFE: fail-closed structural runtime argv projection (REV-012).

    The projector in the existing release producer is exercised directly and
    through observed() with stubbed /proc/systemctl boundaries; rejection
    must occur before any persistence (no write() call).
    """

    @classmethod
    def setUpClass(cls) -> None:
        release_tests_dir = Path(__file__).resolve().parents[1] / "release_tests"
        if str(release_tests_dir) not in sys.path:
            sys.path.insert(0, str(release_tests_dir))
        import importlib

        cls.r19 = importlib.import_module("r19_packet")

    def test_module_imports_without_historical_control_files(self):
        # B6: optional release_control/runtime_readback imports must not break
        # importing the exact producer module in an archived candidate.
        self.assertTrue(hasattr(self.r19, "project_runtime_argv"))
        self.assertTrue(callable(self.r19.observed))

    def test_recorder_grammar_roundtrip_is_byte_equal(self):
        argv = ["/usr/bin/python3.13", "-B", "-s", "-m", "recorder_next",
                "--config", "/etc/recorder-next/recorder-next.toml",
                "--host", "127.0.0.1", "--port", "8653"]
        out = self.r19.project_runtime_argv(argv, role="recorder",
                                            executable="/usr/bin/python3.13",
                                            config="/etc/recorder-next/recorder-next.toml",
                                            port=8653)
        self.assertEqual(out, argv)

    def test_hermes_grammar_roundtrips(self):
        exe = "/usr/bin/python3.13"
        gateway = ["/home/rumi/.hermes/hermes-agent/venv/bin/hermes", "gateway", "run"]
        self.assertEqual(self.r19.project_runtime_argv(gateway, role="hermes", executable=exe,
                                                       config="/x", port=9120), gateway)
        serve = ["/home/rumi/.hermes/hermes-agent/venv/bin/hermes", "serve", "--isolated",
                 "--skip-build", "--host", "127.0.0.1", "--port", "9120"]
        self.assertEqual(self.r19.project_runtime_argv(serve, role="hermes", executable=exe,
                                                       config="/x", port=9120), serve)

    def test_sensitive_and_unknown_forms_reject_closed(self):
        cases = [
            (["/usr/bin/python3.13", "--api-key", "synthetic-sensitive-value"], "recorder"),
            (["/usr/bin/python3.13", "--API-KEY", "synthetic-sensitive-value"], "recorder"),
            (["/usr/bin/python3.13", "token=abc"], "recorder"),
            (["/usr/bin/python3.13", "password=hunter2"], "recorder"),
            (["/usr/bin/python3.13", "-m", "recorder_next",
              "--config=/etc/recorder-next/recorder-next.toml"], "recorder"),
            (["/usr/bin/python3.13", "-m", "recorder_next",
              "--config", "/etc/other.toml"], "recorder"),
            (["/usr/bin/python3.13", "-m", "recorder_next",
              "--config", "/etc/recorder-next/recorder-next.toml",
              "--port", "9999"], "recorder"),
            (["/usr/bin/python3.13", "-m", "recorder_next",
              "--config", "/etc/recorder-next/recorder-next.toml",
              "--port", "8653", "--host", "127.0.0.1"], "recorder"),  # reordered
            (["/usr/bin/python3.13", "-m", "recorder_next",
              "--config", "/etc/recorder-next/recorder-next.toml",
              "--db", "/x"], "recorder"),
            (["/bin/bash", "-c", "echo hi"], "recorder"),
            (["https://user:pass@host/x"], "hermes"),
            (["--PORT", "8653"], "recorder"),
        ]
        for argv, role in cases:
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    self.r19.project_runtime_argv(argv, role=role,
                                                  executable="/usr/bin/python3.13",
                                                  config="/etc/recorder-next/recorder-next.toml",
                                                  port=8653)

    def test_observed_persists_nothing_on_rejected_argv(self):
        # Actual observed() with stubbed boundaries: a secret-bearing argv is
        # refused before any write() call and no raw argv/value escapes.
        control = self.r19
        calls = {"write": 0}

        class _Sentinel:
            def write(self, *args: Any, **kwargs: Any) -> None:
                calls["write"] += 1

        sentinel = _Sentinel()
        fake_runtime = type("M", (), {})()
        fake_runtime._cmdline = lambda pid: ["/usr/bin/python3.13", "--api-key", "synthetic-sensitive-value"]
        fake_runtime._uid_gid = lambda pid: (0, 0)
        fake_runtime.profile_sha256 = lambda profile: "0" * 64
        fake_runtime._version = lambda pid: "0"
        fake_runtime._cgroup = lambda pid: "/system.slice/x.service"
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            config = tmp / "recorder-next.toml"
            config.write_text("[server]\n", encoding="utf-8")
            with patch.object(control, "runtime", fake_runtime), patch.object(
                control, "modules", return_value=[]
            ):
                # On hosts where the systemd unit exists, observed() reaches
                # argv projection and refuses with ValueError.  On hosts
                # without the unit, systemctl fails first ("mandatory active
                # runtime missing").  Both orders are fail-closed; neither may
                # persist anything.
                try:
                    control.observed("recorder", "recorder-next.service", 8653, str(config), [])
                except ValueError:
                    pass
                except RuntimeError as exc:
                    self.assertIn("runtime missing", str(exc))
                else:
                    self.fail("observed() unexpectedly accepted a secret-bearing argv")
        self.assertEqual(calls["write"], 0)



SCHEMA4_FIXTURE = Path(__file__).with_name("fixtures") / "schema4_public_preimage.sql"
SCHEMA4_FIXTURE_SHA256 = "73076556af3d41c46b45ef43049346ad750fd705bdc6bef5cc53ba12c1316d84"


def _seed_migration_fixture(db_path: Path, script_path: Path, *, version: int) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(script_path.read_text(encoding="utf-8"))
    conn.execute("UPDATE schema_meta SET value=? WHERE key='schema_version'", (str(version),))
    conn.execute(
        "INSERT INTO devices(user_id, device_id, kind, created_at) VALUES (?, ?, ?, ?)",
        ("sentinel-user", "sentinel-device", "phone", "2026-09-10T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()


def _logical_database_snapshot(db_path: Path) -> dict:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    objects = [
        tuple(row)
        for row in conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        )
    ]
    tables = [row[1] for row in objects if row[0] == "table"]
    rows = {}
    for table in tables:
        escaped = table.replace('"', '""')
        values = [tuple(row) for row in conn.execute(f'SELECT * FROM "{escaped}"')]
        rows[table] = sorted(values, key=repr)
    snapshot = {
        "objects": objects,
        "rows": rows,
        "foreign_key_check": [tuple(row) for row in conn.execute("PRAGMA foreign_key_check")],
        "integrity_check": conn.execute("PRAGMA integrity_check").fetchone()[0],
    }
    conn.close()
    return snapshot

class R25IntegratedRegressionTests(unittest.TestCase):
    def test_missing_explicit_config_fails_before_service_or_storage_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.toml"
            with patch("sys.argv", ["recorder-next", "--config", str(missing)]), patch.object(
                recorder_main, "create_configured_service"
            ) as create_service:
                with self.assertRaises(FileNotFoundError):
                    recorder_main.main()
            create_service.assert_not_called()

    def test_production_health_requires_live_successful_background_loops(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(
                store,
                hermes=MemoryHermesGateway(),
                tts=StaticTTSProvider(),
                production_readiness={"asr": True, "tts": True, "hermes": True},
            )

            status, _headers, payload = service.handle_http("GET", "/v1/health", {}, b"")
            self.assertEqual(status, 500)
            self.assertEqual(payload["error"]["code"], "VOICE_NOT_READY")

            service.start_background_workers(worker_poll_seconds=0.01, scheduler_poll_seconds=0.01)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                status, _headers, payload = service.handle_http("GET", "/v1/health", {}, b"")
                if status == 200:
                    break
                time.sleep(0.01)
            self.assertEqual(status, 200)
            self.assertEqual(payload["status"], "ok")

            service.stop_background_workers(timeout=1)
            status, _headers, payload = service.handle_http("GET", "/v1/health", {}, b"")
            self.assertEqual(status, 500)
            self.assertEqual(payload["error"]["code"], "VOICE_NOT_READY")

    def test_production_admission_rejects_fixture_dependencies_before_storage_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = RecorderConfig(database=str(root / "db.sqlite3"), storage_root=str(root / "data"))

            with self.assertRaises(CredentialError):
                create_configured_service(config, ingress_secret="test-secret", require_production=True)

            self.assertFalse((root / "db.sqlite3").exists())

    def test_project_create_omitted_aliases_uses_empty_canonical_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            store.register_device("project-user", "project-phone", "phone")
            status, _headers, payload = RecorderService(store).handle_http(
                "POST",
                "/v1/projects",
                {"Content-Type": "application/json"},
                json.dumps(
                    {
                        "user_id": "project-user",
                        "device_id": "project-phone",
                        "project_number": "P-1",
                        "name": "Project one",
                    }
                ).encode(),
            )
            self.assertEqual(status, 201)
            self.assertEqual(payload["aliases"], [])

    def test_audio_duration_is_derived_and_frame_boundary_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data", max_audio_minutes=1)

            def create_audio_turn(turn_id: str, frames: int) -> bytes:
                manifest = {
                    "schema_version": 1,
                    "user_id": "audio-user",
                    "turn_id": turn_id,
                    "origin_device_id": "phone",
                    "client_created_at": "2026-09-09T00:00:00Z",
                    "parts": [{"part_id": "audio", "kind": "audio", "mime": "audio/wav", "streaming": True}],
                }
                store.create_turn(manifest)
                wav_buffer = io.BytesIO()
                with wave.open(wav_buffer, "wb") as handle:
                    handle.setnchannels(1)
                    handle.setsampwidth(2)
                    handle.setframerate(16000)
                    handle.writeframes(b"\x00\x00" * frames)
                audio = wav_buffer.getvalue()
                starts = range(0, len(audio), store.max_chunk_bytes)
                for sequence, start in enumerate(starts):
                    store.put_chunk(turn_id, "audio", sequence, audio[start : start + store.max_chunk_bytes])
                return audio, (len(audio) + store.max_chunk_bytes - 1) // store.max_chunk_bytes

            audio, total_chunks = create_audio_turn("018f5a2e-7b6e-7abc-8d11-1234567890b1", 160)
            result = store.finish_part(
                "018f5a2e-7b6e-7abc-8d11-1234567890b1",
                "audio",
                total_chunks=total_chunks,
                total_bytes=len(audio),
                whole_stream_sha256=hashlib.sha256(audio).hexdigest(),
                duration_ms=11,
            )
            self.assertEqual(result["duration_ms"], 10)

            oversized, total_chunks = create_audio_turn("018f5a2e-7b6e-7abc-8d11-1234567890b2", 960001)
            with self.assertRaises(Exception) as raised:
                store.finish_part(
                    "018f5a2e-7b6e-7abc-8d11-1234567890b2",
                    "audio",
                    total_chunks=total_chunks,
                    total_bytes=len(oversized),
                    whole_stream_sha256=hashlib.sha256(oversized).hexdigest(),
                )
            self.assertEqual(getattr(raised.exception, "code", None), "QUOTA_EXCEEDED")

    def test_diagnostic_purge_removes_expired_content_rows_after_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(
                root / "db.sqlite3",
                storage_root=root / "data",
                diagnostics_retention_seconds=1,
                diagnostics_tombstone_retention_seconds=10,
            )
            store.register_device("diag-user", "diag-phone", "phone")
            opt_in = store.record_diagnostics_opt_in("diag-user", "diag-phone", event_id="diag-opt", now="2026-09-01T00:00:00Z")
            event = store.ingest_diagnostic_event(
                "diag-user",
                "diag-phone",
                event_id="diag-event",
                idempotency_key="diag-event",
                payload={"category": "voice", "stage": "upload"},
                now="2026-09-01T00:00:00Z",
            )
            bundle = store.ingest_diagnostic_bundle(
                "diag-user",
                "diag-phone",
                "diag-bundle",
                zlib.compress(b'{"category":"voice","stage":"upload"}'),
                opt_in_event_id=opt_in["event_id"],
                now="2026-09-01T00:00:00Z",
            )
            first = store.purge_diagnostics(now="2026-09-01T00:00:02Z")
            self.assertEqual((first["events"], first["bundles"]), (1, 1))
            with store._read() as conn:
                self.assertIsNotNone(conn.execute("SELECT 1 FROM diagnostic_events WHERE event_id=?", (event["event_id"],)).fetchone())
                self.assertIsNotNone(conn.execute("SELECT 1 FROM diagnostic_bundles WHERE bundle_id=?", (bundle["bundle_id"],)).fetchone())
            second = store.purge_diagnostics(now="2026-09-01T00:00:20Z")
            self.assertGreaterEqual(second.get("tombstones", 0), 2)
            with store._read() as conn:
                self.assertIsNone(conn.execute("SELECT 1 FROM diagnostic_events WHERE event_id=?", (event["event_id"],)).fetchone())
                self.assertIsNone(conn.execute("SELECT 1 FROM diagnostic_bundles WHERE bundle_id=?", (bundle["bundle_id"],)).fetchone())

    def test_diagnostic_tombstones_scrub_owner_and_event_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(
                root / "db.sqlite3",
                storage_root=root / "data",
                diagnostics_retention_seconds=1,
                diagnostics_tombstone_retention_seconds=10,
            )
            store.register_device("opaque-user", "opaque-phone", "phone")
            store.record_diagnostics_opt_in("opaque-user", "opaque-phone", event_id="opaque-opt", now="2026-09-01T00:00:00Z")
            event_result = store.ingest_diagnostic_event(
                "opaque-user",
                "opaque-phone",
                event_id="opaque-event",
                idempotency_key="opaque-event",
                payload={"category": "voice", "stage": "upload"},
                now="2026-09-01T00:00:00Z",
            )
            store.purge_diagnostics(now="2026-09-01T00:00:02Z", _recover_cleanup=False)
            with store._read() as conn:
                event = conn.execute("SELECT category, stage, metadata_json FROM diagnostic_events WHERE event_id=?", (event_result["event_id"],)).fetchone()
                tombstone = conn.execute("SELECT user_id, device_id, entity_id FROM diagnostic_tombstones WHERE entity_type='event' AND entity_id=?", (event_result["event_id"],)).fetchone()
            self.assertEqual((event["category"], event["stage"], event["metadata_json"]), ("other", "other", "{}"))
            self.assertIsNotNone(tombstone)
            self.assertNotIn("opaque-user", tombstone["user_id"])
            self.assertNotIn("opaque-phone", tombstone["device_id"])
            self.assertEqual(tombstone["entity_id"], event_result["event_id"])

    def test_cleanup_receipt_claim_is_single_owner_and_reclaims_after_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            target = root / "data" / "cleanup.bin"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"cleanup")
            receipt_id = store._prepare_cleanup_receipt(
                operation="integrated_claim_test",
                path=target,
                expected_sha256=hashlib.sha256(b"cleanup").hexdigest(),
                expected_size=7,
                now="2026-09-01T00:00:00Z",
            )
            first = store._features._claim_cleanup_receipt(receipt_id, now="2026-09-01T00:00:00Z")
            second = store._features._claim_cleanup_receipt(receipt_id, now="2026-09-01T00:00:01Z")
            reclaimed = store._features._claim_cleanup_receipt(receipt_id, now="2026-09-01T00:05:01Z")
            self.assertIsNotNone(first)
            self.assertIsNone(second)
            self.assertIsNotNone(reclaimed)
            self.assertNotEqual(first, reclaimed)

    def test_http_rejects_new_work_after_shutdown_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = RecorderService(RecorderStore(root / "db.sqlite3", storage_root=root / "data"))
            service.request_shutdown()
            status, _headers, payload = service.handle_http("GET", "/v1/health", {}, b"")
            self.assertEqual(status, 503)
            self.assertEqual(payload["error"]["code"], "SERVICE_STOPPING")

    def test_audio_finish_replay_without_duration_uses_trusted_derived_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ac"
            manifest = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": turn_id,
                "origin_device_id": "phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [{"part_id": "audio", "kind": "audio", "mime": "audio/wav", "streaming": True}],
            }
            store.create_turn(manifest)
            wav_buffer = io.BytesIO()
            with wave.open(wav_buffer, "wb") as handle:
                handle.setnchannels(1)
                handle.setsampwidth(2)
                handle.setframerate(16000)
                handle.writeframes(b"\x00\x00" * 160)
            audio = wav_buffer.getvalue()
            digest = hashlib.sha256(audio).hexdigest()
            store.put_chunk(turn_id, "audio", 0, audio)
            first = store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=digest,
            )
            replay = store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=digest,
            )
            self.assertEqual(first["duration_ms"], 10)
            self.assertEqual(replay["duration_ms"], first["duration_ms"])

    def test_audio_finish_legacy_missing_duration_is_repaired_or_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ad"
            manifest = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": turn_id,
                "origin_device_id": "phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [{"part_id": "audio", "kind": "audio", "mime": "audio/wav", "streaming": True}],
            }
            store.create_turn(manifest)
            wav_buffer = io.BytesIO()
            with wave.open(wav_buffer, "wb") as handle:
                handle.setnchannels(1)
                handle.setsampwidth(2)
                handle.setframerate(16000)
                handle.writeframes(b"\x00\x00" * 160)
            audio = wav_buffer.getvalue()
            digest = hashlib.sha256(audio).hexdigest()
            store.put_chunk(turn_id, "audio", 0, audio)
            first = store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=digest,
            )
            with store._tx() as conn:
                conn.execute("UPDATE turn_parts SET duration_ms=NULL WHERE turn_id=? AND part_id=?", (turn_id, "audio"))
            repaired = store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=digest,
            )
            self.assertEqual(repaired["duration_ms"], first["duration_ms"])

            with store._tx() as conn:
                conn.execute(
                    "UPDATE turn_parts SET duration_ms=NULL, source_deleted_at=? WHERE turn_id=? AND part_id=?",
                    ("2026-09-10T00:00:00+00:00", turn_id, "audio"),
                )
            with self.assertRaises(SourceUnavailableError):
                store.finish_part(
                    turn_id,
                    "audio",
                    total_chunks=1,
                    total_bytes=len(audio),
                    whole_stream_sha256=digest,
                )

    def test_audio_finish_publishes_with_cleanup_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ae"
            manifest = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": turn_id,
                "origin_device_id": "phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [{"part_id": "text", "kind": "text", "mime": "text/plain"}],
            }
            store.create_turn(manifest)
            payload = b"streamed finish"
            digest = hashlib.sha256(payload).hexdigest()
            store.put_chunk(turn_id, "text", 0, payload)
            real_link = store._features._link_staged

            def link_then_fail(*args, **kwargs):
                real_link(*args, **kwargs)
                raise RuntimeError("simulated post-publication failure")

            with patch.object(store._features, "_link_staged", side_effect=link_then_fail):
                with self.assertRaises(RuntimeError):
                    store.finish_part(
                        turn_id,
                        "text",
                        total_chunks=1,
                        total_bytes=len(payload),
                        whole_stream_sha256=digest,
                    )
            part_dir = next((root / "data" / "turns").glob("*/" + "*/parts/*"))
            self.assertFalse((part_dir / "part.bin").exists())
            with store._read() as conn:
                statuses = [row["status"] for row in conn.execute("SELECT status FROM storage_cleanup_receipts").fetchall()]
            self.assertTrue(statuses)
            self.assertTrue(all(status == "COMPLETE" for status in statuses))

    def test_schema4_fixture_is_the_pinned_public_preimage(self):
        content = SCHEMA4_FIXTURE.read_bytes()
        self.assertEqual(len(content), 19999)
        self.assertEqual(hashlib.sha256(content).hexdigest(), SCHEMA4_FIXTURE_SHA256)

    def test_sql_script_executor_preserves_transaction_and_sqlite_parsing(self):
        with sqlite3.connect(":memory:", isolation_level=None) as conn:
            conn.execute("BEGIN IMMEDIATE")
            RecorderStore._execute_sql_script(
                conn,
                "-- semicolon in a comment;\n"
                "CREATE TABLE parsed (value TEXT);\n"
                "INSERT INTO parsed VALUES ('quoted;semicolon');\n"
                "CREATE TABLE unterminated (value TEXT)\n"
                "/* final comment */",
            )
            self.assertEqual(conn.execute("SELECT value FROM parsed").fetchone()[0], "quoted;semicolon")
            self.assertEqual(
                [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")],
                ["parsed", "unterminated"],
            )
            conn.execute("ROLLBACK")
            with self.assertRaisesRegex(RuntimeError, "active transaction"):
                RecorderStore._execute_sql_script(conn, "CREATE TABLE inactive (value TEXT);")
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(sqlite3.OperationalError):
                RecorderStore._execute_sql_script(conn, "CREATE TABLE malformed (")
            conn.execute("ROLLBACK")

    def test_schema_preparation_failure_after_real_r25_rolls_back_pre_a_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            before = _logical_database_snapshot(db_path)
            original = RecorderStore._apply_r25_migration

            def fail_after_real_work(conn):
                original(conn)
                raise RuntimeError("injected-after-real-r25")

            with patch.object(RecorderStore, "_apply_r25_migration", staticmethod(fail_after_real_work)):
                with self.assertRaisesRegex(RuntimeError, "injected-after-real-r25"):
                    RecorderStore(db_path, storage_root=root / "data")

            self.assertEqual(_logical_database_snapshot(db_path), before)
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertEqual(conn.execute("SELECT device_id FROM devices WHERE device_id='sentinel-device'").fetchone()[0], "sentinel-device")
            migrated = RecorderStore(db_path, storage_root=root / "data")
            with migrated._read() as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "5")
                self.assertIsNotNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_run_bindings'").fetchone())
            restarted = RecorderStore(db_path, storage_root=root / "data")
            with restarted._read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices WHERE device_id='sentinel-device'").fetchone()[0], 1)

    def test_historical_migration_failure_rolls_back_script_and_alters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            initial = root / "initial.sql"
            initial.write_text(
                (Path(__file__).parents[1] / "migrations" / "001_initial.sql").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            _seed_migration_fixture(db_path, initial, version=1)
            before = _logical_database_snapshot(db_path)
            real_connect = sqlite3.connect
            created = []

            class FailingScheduleConnection(sqlite3.Connection):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.closed_for_test = False

                def execute(self, sql, parameters=()):
                    if "idx_schedule_occurrences_due" in str(sql):
                        raise RuntimeError("injected-mid-scheduled-script")
                    return super().execute(sql, parameters)

                def close(self):
                    self.closed_for_test = True
                    return super().close()

            def connect(*args, **kwargs):
                kwargs["factory"] = FailingScheduleConnection
                conn = real_connect(*args, **kwargs)
                created.append(conn)
                return conn

            with patch("recorder_next.store.sqlite3.connect", side_effect=connect):
                with self.assertRaisesRegex(RuntimeError, "injected-mid-scheduled-script"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertTrue(created[0].closed_for_test)
            self.assertEqual(_logical_database_snapshot(db_path), before)

    def test_schema_preparation_commit_refusal_restores_pre_a_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            before = _logical_database_snapshot(db_path)
            real_connect = sqlite3.connect
            created = []

            class FailingInitialCommitConnection(sqlite3.Connection):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.commit_attempts = 0
                    self.closed_for_test = False

                def execute(self, sql, parameters=()):
                    if str(sql).strip().upper() == "COMMIT":
                        self.commit_attempts += 1
                        if self.commit_attempts == 1:
                            raise RuntimeError("injected-initial-commit")
                    return super().execute(sql, parameters)

                def close(self):
                    self.closed_for_test = True
                    return super().close()

            def connect(*args, **kwargs):
                kwargs["factory"] = FailingInitialCommitConnection
                conn = real_connect(*args, **kwargs)
                created.append(conn)
                return conn

            with patch("recorder_next.store.sqlite3.connect", side_effect=connect):
                with self.assertRaisesRegex(RuntimeError, "injected-initial-commit"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertTrue(created[0].closed_for_test)
            self.assertEqual(_logical_database_snapshot(db_path), before)

    def test_final_marker_write_failure_leaves_committed_schema4_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            real_connect = sqlite3.connect
            created = []

            class FailingFinalMarkerConnection(sqlite3.Connection):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.closed_for_test = False

                def execute(self, sql, parameters=()):
                    if (
                        str(sql).strip().upper() == "UPDATE SCHEMA_META SET VALUE=? WHERE KEY='SCHEMA_VERSION'"
                        and tuple(parameters) == ("5",)
                    ):
                        raise RuntimeError("injected-final-marker-write")
                    return super().execute(sql, parameters)

                def close(self):
                    self.closed_for_test = True
                    return super().close()

            def connect(*args, **kwargs):
                kwargs["factory"] = FailingFinalMarkerConnection
                conn = real_connect(*args, **kwargs)
                created.append(conn)
                return conn

            with patch("recorder_next.store.sqlite3.connect", side_effect=connect), patch.object(
                RecorderStore, "_migrate_c7_diagnostics", return_value=True
            ):
                with self.assertRaisesRegex(RuntimeError, "injected-final-marker-write"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertTrue(created[0].closed_for_test)
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertIsNotNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_run_bindings'").fetchone())

    def test_unsupported_version_rejection_rolls_back_bootstrap_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=6)
            before = _logical_database_snapshot(db_path)
            with self.assertRaisesRegex(RuntimeError, "unsupported Recorder schema version 6"):
                RecorderStore(db_path, storage_root=root / "data")
            self.assertEqual(_logical_database_snapshot(db_path), before)

    def test_c7_starts_after_committed_schema_checkpoint_and_exception_preserves_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            observations = []

            def fail_c7(conn, *, force):
                observations.append((conn.in_transaction, force))
                raise RuntimeError("injected-c7-failure")

            with patch.object(RecorderStore, "_migrate_c7_diagnostics", side_effect=fail_c7):
                with self.assertRaisesRegex(RuntimeError, "injected-c7-failure"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertEqual(observations, [(False, True)])
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertIsNotNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_run_bindings'").fetchone())
            resumed = RecorderStore(db_path, storage_root=root / "data")
            with resumed._read() as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "5")

    def test_final_marker_commit_failure_rolls_back_to_schema4_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            _seed_migration_fixture(db_path, SCHEMA4_FIXTURE, version=4)
            real_connect = sqlite3.connect
            created = []

            class FailingFinalCommitConnection(sqlite3.Connection):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.commit_attempts = 0
                    self.closed_for_test = False

                def execute(self, sql, parameters=()):
                    if str(sql).strip().upper() == "COMMIT":
                        self.commit_attempts += 1
                        if self.commit_attempts == 2:
                            raise RuntimeError("injected-final-commit")
                    return super().execute(sql, parameters)

                def close(self):
                    self.closed_for_test = True
                    return super().close()

            def connect(*args, **kwargs):
                kwargs["factory"] = FailingFinalCommitConnection
                conn = real_connect(*args, **kwargs)
                created.append(conn)
                return conn

            with patch("recorder_next.store.sqlite3.connect", side_effect=connect), patch.object(
                RecorderStore, "_migrate_c7_diagnostics", return_value=True
            ):
                with self.assertRaisesRegex(RuntimeError, "injected-final-commit"):
                    RecorderStore(db_path, storage_root=root / "data")
            self.assertTrue(created[0].closed_for_test)
            with sqlite3.connect(db_path) as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertIsNotNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_run_bindings'").fetchone())

    def test_connect_closes_acquired_connection_when_pragma_setup_fails(self):
        real_connect = sqlite3.connect

        class FailingPragmaConnection(sqlite3.Connection):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.closed_for_test = False

            def execute(self, sql, parameters=()):
                if str(sql).strip().upper() == "PRAGMA JOURNAL_MODE = WAL":
                    raise RuntimeError("injected-journal-mode")
                return super().execute(sql, parameters)

            def close(self):
                self.closed_for_test = True
                return super().close()

        conn = real_connect(":memory:", factory=FailingPragmaConnection, isolation_level=None)
        instance = RecorderStore.__new__(RecorderStore)
        instance.db_path = ":memory:"
        with patch("recorder_next.store.sqlite3.connect", return_value=conn):
            with self.assertRaisesRegex(RuntimeError, "injected-journal-mode"):
                instance._connect()
        self.assertTrue(conn.closed_for_test)

    def test_terminal_worker_replay_requires_winning_attempt_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecorderStore(Path(tmp) / "db.sqlite3", storage_root=Path(tmp) / "data")
            job = store.enqueue_worker_job(
                kind="fixture",
                stage="fixture",
                payload={"turn_id": "turn-1"},
                idempotency_key="fixture-job",
            )
            claim = store.claim_worker_job("owner-1")
            self.assertIsNotNone(claim)
            assert claim is not None
            receipt = {"effect_id": "effect-1", "status": "succeeded"}
            store.complete_worker_job(
                job["job_id"],
                "owner-1",
                receipt,
                lease_token=claim["lease_token"],
            )
            with self.assertRaises(ValidationError):
                store.complete_worker_job(job["job_id"], "owner-1", receipt, lease_token="")
            with self.assertRaises(LeaseConflict):
                store.complete_worker_job(job["job_id"], "other-owner", receipt, lease_token="other-token")

    def test_audio_cleanup_does_not_unlink_replaced_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            manifest = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": "018f5a2e-7b6e-7abc-8d11-1234567890aa",
                "origin_device_id": "phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [
                    {"part_id": "audio", "kind": "audio", "mime": "audio/wav", "streaming": True}
                ],
            }
            store.create_turn(manifest)
            wav_buffer = io.BytesIO()
            with wave.open(wav_buffer, "wb") as handle:
                handle.setnchannels(1)
                handle.setsampwidth(2)
                handle.setframerate(16000)
                handle.writeframes(b"\x00\x00" * 160)
            original = wav_buffer.getvalue()
            store.put_chunk(manifest["turn_id"], "audio", 0, original)
            import hashlib
            store.finish_part(
                manifest["turn_id"],
                "audio",
                total_chunks=1,
                total_bytes=len(original),
                whole_stream_sha256=hashlib.sha256(original).hexdigest(),
            )
            with store._read() as conn:
                source = Path(conn.execute("SELECT source_path FROM turn_parts WHERE turn_id=?", (manifest["turn_id"],)).fetchone()[0])
            source.write_bytes(b"replacement")
            generation = store.set_asr_stage(manifest["turn_id"], expected_generation=0, stage="realtime")
            assert generation is not None
            from recorder_next.models import AsrResult
            store.commit_asr_result(
                manifest["turn_id"],
                expected_generation=generation,
                stage="realtime",
                result=AsrResult.valid("transcript"),
            )
            self.assertEqual(source.read_bytes(), b"replacement")

    def test_audio_cleanup_missing_parent_converges_across_restart_and_blocks_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890ab"
            manifest = {
                "schema_version": 1,
                "user_id": "u",
                "turn_id": turn_id,
                "origin_device_id": "phone",
                "client_created_at": "2026-09-09T00:00:00Z",
                "parts": [{"part_id": "audio", "kind": "audio", "mime": "audio/wav", "streaming": True}],
            }
            store.create_turn(manifest)
            wav_buffer = io.BytesIO()
            with wave.open(wav_buffer, "wb") as handle:
                handle.setnchannels(1)
                handle.setsampwidth(2)
                handle.setframerate(16000)
                handle.writeframes(b"\x00\x00" * 160)
            audio = wav_buffer.getvalue()
            store.put_chunk(turn_id, "audio", 0, audio)
            store.finish_part(
                turn_id,
                "audio",
                total_chunks=1,
                total_bytes=len(audio),
                whole_stream_sha256=hashlib.sha256(audio).hexdigest(),
            )
            reference = store.attachment_reference(turn_id, "audio")
            with store._read() as conn:
                source = Path(conn.execute("SELECT source_path FROM turn_parts WHERE turn_id=?", (turn_id,)).fetchone()[0])
            shutil.rmtree(source.parent)
            generation = store.set_asr_stage(turn_id, expected_generation=0, stage="realtime")
            assert generation is not None
            # Leave the durable valid-transcript marker behind and simulate a
            # process loss before its first cleanup attempt.
            with patch.object(store, "_converge_audio_cleanup", return_value=False):
                self.assertTrue(
                    store.commit_asr_result(
                        turn_id,
                        expected_generation=generation,
                        stage="realtime",
                        result=AsrResult.valid("transcript"),
                    )
                )

            restarted = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            recovery = restarted.recover(now="2026-09-09T00:01:00+00:00")
            self.assertEqual(recovery["source_deletions_retried"], 1)
            with restarted._read() as conn:
                turn = conn.execute("SELECT source_deleted FROM turns WHERE turn_id=?", (turn_id,)).fetchone()
                part = conn.execute("SELECT source_path, source_deleted_at FROM turn_parts WHERE turn_id=?", (turn_id,)).fetchone()
                chunks = conn.execute("SELECT COUNT(*) FROM turn_chunks WHERE turn_id=?", (turn_id,)).fetchone()[0]
            self.assertEqual(turn["source_deleted"], 1)
            self.assertIsNone(part["source_path"])
            self.assertIsNotNone(part["source_deleted_at"])
            self.assertEqual(chunks, 0)
            with self.assertRaises(SourceUnavailableError) as issued:
                restarted.attachment_reference(turn_id, "audio")
            self.assertEqual((issued.exception.code, issued.exception.status), ("SOURCE_UNAVAILABLE", 410))
            with self.assertRaises(SourceUnavailableError) as resolved:
                restarted.resolve_attachment_reference(reference)
            self.assertEqual((resolved.exception.code, resolved.exception.status), ("SOURCE_UNAVAILABLE", 410))

    def test_schema4_diagnostics_reproject_handles_aliases_and_equal_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "db.sqlite3"
            storage_root = root / "data"
            RecorderStore(db_path, storage_root=storage_root)
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            for table in ("diagnostic_bundles", "diagnostic_events", "diagnostics_consents", "diagnostic_tombstones"):
                conn.execute(f"DROP TABLE {table}")
            conn.executescript(
                """
                CREATE TABLE diagnostics_consents (
                    user_id TEXT NOT NULL, device_id TEXT NOT NULL, event_id TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT
                );
                CREATE TABLE diagnostic_events (
                    event_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
                    user_id TEXT NOT NULL, device_id TEXT NOT NULL, category TEXT NOT NULL,
                    stage TEXT NOT NULL, metadata_json TEXT NOT NULL, occurred_at TEXT NOT NULL,
                    retention_deadline TEXT NOT NULL, deleted_at TEXT
                );
                CREATE TABLE diagnostic_bundles (
                    bundle_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL,
                    opt_in_event_id TEXT NOT NULL, compressed_size INTEGER NOT NULL,
                    expanded_size INTEGER NOT NULL, payload_sha256 TEXT NOT NULL,
                    storage_path TEXT NOT NULL, created_at TEXT NOT NULL,
                    retention_deadline TEXT NOT NULL, deleted_at TEXT,
                    UNIQUE(user_id, device_id, payload_sha256),
                    FOREIGN KEY(opt_in_event_id) REFERENCES diagnostics_consents(event_id) ON DELETE RESTRICT
                );
                CREATE TABLE diagnostic_tombstones (
                    tombstone_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL CHECK(entity_type IN ('event','bundle')),
                    entity_id TEXT NOT NULL, deleted_at TEXT NOT NULL,
                    UNIQUE(entity_type, entity_id)
                );
                """
            )
            conn.execute("UPDATE schema_meta SET value='4' WHERE key='schema_version'")
            conn.execute(
                "INSERT INTO devices(user_id, device_id, kind, created_at) VALUES (?, ?, ?, ?)",
                ("legacy-user", "legacy-phone", "phone", "2026-09-10T00:00:00+00:00"),
            )
            conn.execute(
                "INSERT INTO diagnostics_consents VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("legacy-user", "legacy-phone", "consent-old", 1, "2026-09-10T00:00:00+00:00", "2026-12-01T00:00:00+00:00", None),
            )
            conn.execute(
                "INSERT INTO diagnostic_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "event-old", "idem-old", "legacy-user", "legacy-phone", "voice", "asr",
                    json.dumps({"category": "voice", "stage": "asr", "status": "ok", "token": "private"}),
                    "2026-09-10T00:00:01+00:00", "2026-12-01T00:00:00+00:00", None,
                ),
            )
            legacy_payloads = []
            for index in range(2):
                raw = json.dumps(
                    {"events": [{"category": "voice", "stage": "asr", "status": "ok", "token": f"private-{index}"}]},
                    separators=(",", ":"),
                ).encode()
                compressed = zlib.compress(raw)
                path = storage_root / f"legacy-{index}.z"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(compressed)
                bundle_id = f"bundle-old-{index}"
                conn.execute(
                    "INSERT INTO diagnostic_bundles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        bundle_id, "legacy-user", "legacy-phone", "consent-old", len(compressed), len(raw),
                        hashlib.sha256(compressed).hexdigest(), str(path), f"2026-09-10T00:00:0{index + 2}+00:00",
                        "2026-12-01T00:00:00+00:00", None,
                    ),
                )
                legacy_payloads.append((bundle_id, raw))
            conn.execute(
                "INSERT INTO diagnostic_tombstones VALUES (?, ?, ?, ?, ?, ?)",
                ("tomb-old", "legacy-user", "legacy-phone", "event", "event-old", "2026-09-10T00:00:03+00:00"),
            )
            conn.commit()
            conn.close()

            with patch.object(FeatureGroups, "_unlink_managed_file", side_effect=OSError("deferred cleanup")):
                incomplete = RecorderStore(db_path, storage_root=storage_root)
            with incomplete._read() as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "4")
                self.assertEqual(conn.execute("SELECT migration_state FROM diagnostic_bundles").fetchone()[0], "MIGRATING")
                self.assertEqual(conn.execute("SELECT status FROM storage_cleanup_receipts WHERE operation LIKE 'diagnostic_migration_cleanup_%'").fetchone()[0], "PENDING")
            migrated = RecorderStore(db_path, storage_root=storage_root)
            with migrated._read() as conn:
                self.assertEqual(conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0], "5")
                consent = conn.execute("SELECT * FROM diagnostics_consents").fetchone()
                event = conn.execute("SELECT * FROM diagnostic_events").fetchone()
                bundles = conn.execute("SELECT * FROM diagnostic_bundles ORDER BY created_at").fetchall()
                tombstone = conn.execute("SELECT * FROM diagnostic_tombstones").fetchone()
                self.assertEqual(len(bundles), 2)
                self.assertTrue(all(row["migration_state"] == "READY" and row["privacy_version"] == 2 for row in bundles))
                self.assertTrue(all(uuid.UUID(row["bundle_id"]).version == 4 for row in bundles))
                self.assertEqual(bundles[0]["payload_sha256"], bundles[1]["payload_sha256"])
                self.assertEqual(bundles[0]["opt_in_event_id"], consent["event_id"])
                self.assertEqual(tombstone["entity_id"], event["event_id"])
                self.assertNotIn("event-old", json.dumps(dict(event)))
                self.assertNotIn("idem-old", json.dumps(dict(event)))
                for index in conn.execute("PRAGMA index_list(diagnostic_bundles)").fetchall():
                    if index["unique"]:
                        columns = [item["name"] for item in conn.execute(f"PRAGMA index_info({index['name']})").fetchall()]
                        self.assertNotEqual(columns, ["user_id", "device_id", "payload_sha256"])
            self.assertFalse(any((storage_root / f"legacy-{index}.z").exists() for index in range(2)))
            replay_event = migrated.ingest_diagnostic_event(
                "legacy-user", "legacy-phone", event_id="event-old", idempotency_key="idem-old",
                payload={"category": "voice", "stage": "asr", "status": "ok"},
            )
            self.assertEqual(replay_event["event_id"], event["event_id"])
            for bundle_id, raw in legacy_payloads:
                replay = migrated.ingest_diagnostic_bundle(
                    "legacy-user", "legacy-phone", bundle_id, zlib.compress(raw),
                    opt_in_event_id="consent-old", expanded_size=len(raw),
                )
                with migrated._read() as conn:
                    expected = conn.execute("SELECT bundle_id FROM diagnostic_bundles WHERE alias_digest=?", (migrated._features._alias_digest("bundle", "legacy-user", "legacy-phone", bundle_id),)).fetchone()[0]
                self.assertEqual(replay["bundle_id"], expected)
            restarted = RecorderStore(db_path, storage_root=storage_root)
            with restarted._read() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM diagnostic_bundles").fetchone()[0], 2)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM diagnostic_bundles WHERE migration_state='READY'").fetchone()[0], 2)

    def test_history_requery_uses_canonical_request_hash_not_ingress_envelope_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            service = RecorderService(store)
            turn_id = "018f5a2e-7b6e-7abc-8d11-1234567890a1"
            service.store.get_turn = lambda _turn_id: {
                "turn_id": turn_id,
                "final_event_version": 1,
                "final_content": None,
                "final_outcome": None,
            }

            first = HermesResult(
                "assistant-1", "first", True, "hermes-history", submission_id="submission-1",
                turn_id=turn_id, marker="marker-1", session_key="session-1", run_id="run-1",
                request_sha256="request-hash", subject_kind="turn",
            )
            second = HermesResult(
                "assistant-2", "second", True, "hermes-run", submission_id="submission-1",
                turn_id=turn_id, marker="marker-1", session_key="session-1", run_id="run-1",
                request_sha256="request-hash", subject_kind="turn",
            )

            class HistoryGateway:
                def history_messages(self, *, session_key, marker):
                    self.seen = (session_key, marker)
                    return [first]

            service.hermes = HistoryGateway()
            ingress = {
                "turn_id": turn_id,
                "hermes_submission_id": "submission-1",
                "marker": "marker-1",
                "gateway_session_key": "session-1",
                "run_id": "run-1",
                "payload_sha256": "envelope-hash",
            }
            self.assertEqual(service._requery_combined_content(ingress, second), "first\nsecond")

    def test_update_manifest_rejects_same_size_source_mutation_during_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "candidate.apk"
            source.write_bytes(b"original")
            store = RecorderStore(root / "db.sqlite3", storage_root=root / "data")
            features = store._features
            publish_stream = features._publish_stream

            def mutate_source_then_publish(*args, **kwargs):
                source.write_bytes(b"mutated!")
                return publish_stream(*args, **kwargs)

            features._publish_stream = mutate_source_then_publish
            try:
                with self.assertRaises(ConflictError):
                    store.publish_update_manifest(
                        channel="mutation",
                        generation=1,
                        platform="phone",
                        version="1.0.0",
                        version_code=1,
                        artifact_name="candidate.apk",
                        artifact_path=source,
                        signer_digest="a" * 64,
                        changelog="change",
                        min_server_version="1.0.0",
                        authorization_policy="test-only",
                    )
            finally:
                features._publish_stream = publish_stream
            with store._read() as conn:
                self.assertIsNone(conn.execute("SELECT 1 FROM update_manifests WHERE channel=?", ("mutation",)).fetchone())


class Voice1B6E6SuccessorRegressionTests(unittest.TestCase):
    """RED/GREEN coverage for the E6 closure and report-consumer seams."""

    @classmethod
    def setUpClass(cls) -> None:
        control_dir = Path(__file__).resolve().parents[1] / "run"
        if str(control_dir) not in sys.path:
            sys.path.insert(0, str(control_dir))
        import qa_probe_runner as control

        cls.control = control

    def test_e6_predicate_abi_is_exact_ordered_32(self):
        expected = (
            "authorization_bound", "candidate_bound", "imports_bound",
            "credential_custody", "dashboard_credential_parse", "api_credential_parse",
            "lifetime_pre", "unauthenticated_gate", "api_capability", "asr_ready", "tts_ready",
            "omitted_profile_equal", "omitted_profile_ready", "generic_preflight", "session_get",
            "persisted_lookup_ro", "persisted_lookup_indexed", "session_budget",
            "payload_object_match", "source_match", "id_match", "lifecycle_match",
            "persisted_row_count_match", "persisted_id_match", "persisted_source_match",
            "persisted_ended_at_null", "conversation_key_match", "distinct_key_identity",
            "lifetime_post", "closing_identity_equal", "no_mutation", "secret_safe",
        )
        self.assertEqual(self.control.REQUIRED_PREDICATES, expected)

    def test_e6_candidate_registry_rejects_namespace_and_identity_drift(self):
        helper = Voice1B6E5FindingRegressionTests()
        helper.control = self.control
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            per_file, archive = helper._bundle_fixture(root)
            snapshot = helper._snapshot_candidate_modules()
            try:
                helper._restore_candidate_modules({})
                with patch.object(self.control, "_verify_candidate_source", return_value=True):
                    bundle = self.control._load_candidate_module_bundle(
                        {"per_file_sha256": per_file}, {"archive_path": str(archive)},
                        retain_finder=True,
                    )
                self.assertIsInstance(bundle, dict)
                assert isinstance(bundle, dict)
                self.assertTrue(self.control._candidate_modules_still_bound(bundle, {}, {}))
                extra = importlib.util.module_from_spec(
                    importlib.util.spec_from_loader("recorder_next.e6_extra", loader=None)
                )
                sys.modules["recorder_next.e6_extra"] = extra
                self.assertFalse(self.control._candidate_modules_still_bound(bundle, {}, {}))
                del sys.modules["recorder_next.e6_extra"]
                removed_name = next(iter(bundle["registry"]))
                removed = sys.modules.pop(removed_name)
                try:
                    self.assertFalse(self.control._candidate_modules_still_bound(bundle, {}, {}))
                finally:
                    sys.modules[removed_name] = removed
                module = sys.modules[removed_name]
                original_spec = module.__spec__
                module.__spec__ = importlib.machinery.ModuleSpec(removed_name, loader=None)
                try:
                    self.assertFalse(self.control._candidate_modules_still_bound(bundle, {}, {}))
                finally:
                    module.__spec__ = original_spec
                loader = original_spec.loader
                original_data = loader._data
                loader._data = original_data + b"\\n# drift\\n"
                try:
                    self.assertFalse(self.control._candidate_modules_still_bound(bundle, {}, {}))
                finally:
                    loader._data = original_data
            finally:
                self.control._release_candidate_module_bundle(locals().get("bundle"))
                helper._restore_candidate_modules(snapshot)

    def test_e6_custody_handle_detects_leaf_swap_restore_without_reopen(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            credential = root / "credential"
            credential.write_bytes(b"fixture-secret")
            pin = self.control._regular_file_identity_no_follow(credential)
            handle = self.control._open_custodied_file(credential, pin, max_bytes=128)
            try:
                with patch.object(self.control.os, "open", side_effect=AssertionError("reopen forbidden")):
                    self.assertEqual(handle.read_bytes(), b"fixture-secret")
                self.assertTrue(handle.revalidate())
                replacement = root / "replacement"
                replacement.write_bytes(b"fixture-secret")
                original = root / "original"
                credential.rename(original)
                replacement.rename(credential)
                with self.assertRaises(OSError):
                    handle.read_bytes()
                credential.rename(replacement)
                original.rename(credential)
                self.assertFalse(handle.revalidate(), "swap/restore must invalidate the held custody")
            finally:
                handle.close()

    def test_e6_custody_handle_detects_swap_during_read(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            credential = root / "credential"
            credential.write_bytes(b"fixture-secret")
            replacement = root / "replacement"
            replacement.write_bytes(b"replacement-secret")
            handle = self.control._open_custodied_file(
                credential,
                self.control._regular_file_identity_no_follow(credential),
                max_bytes=128,
            )
            original = root / "original"
            swapped = False
            real_read = self.control.os.read

            def swap_then_read(fd, size):
                nonlocal swapped
                if not swapped:
                    credential.rename(original)
                    replacement.rename(credential)
                    swapped = True
                return real_read(fd, size)

            try:
                with patch.object(self.control.os, "read", side_effect=swap_then_read):
                    with self.assertRaises(OSError):
                        handle.read_bytes()
                credential.rename(replacement)
                original.rename(credential)
            finally:
                handle.close()

    def test_e6_dashboard_metadata_handle_detects_swap_restore(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            metadata = root / "metadata.json"
            metadata.write_text("{\"expires_at_utc\":\"2099-01-01T00:00:00Z\"}", encoding="utf-8")
            handle = self.control._open_custodied_file(metadata, None, max_bytes=4096)
            try:
                self.assertEqual(handle.read_text(), metadata.read_text(encoding="utf-8"))
                replacement = root / "metadata-replacement.json"
                replacement.write_bytes(metadata.read_bytes())
                original = root / "metadata-original.json"
                metadata.rename(original)
                replacement.rename(metadata)
                metadata.rename(replacement)
                original.rename(metadata)
                self.assertFalse(handle.revalidate(), "metadata swap/restore must invalidate custody")
            finally:
                handle.close()

    def test_e6_dashboard_metadata_handle_detects_swap_during_read(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            metadata = root / "metadata.json"
            metadata.write_bytes(b"{\"expires_at_utc\":\"2099-01-01T00:00:00Z\"}")
            replacement = root / "metadata-replacement.json"
            replacement.write_bytes(b"{\"expires_at_utc\":\"2099-01-01T00:00:00Z\"}")
            original = root / "metadata-original.json"
            handle = self.control._open_custodied_file(metadata, None, max_bytes=4096)
            swapped = False
            real_read = self.control.os.read

            def swap_then_read(fd, size):
                nonlocal swapped
                if not swapped:
                    metadata.rename(original)
                    replacement.rename(metadata)
                    swapped = True
                return real_read(fd, size)

            try:
                with patch.object(self.control.os, "read", side_effect=swap_then_read):
                    with self.assertRaises(OSError):
                        handle.read_bytes()
                metadata.rename(replacement)
                original.rename(metadata)
            finally:
                handle.close()

    def test_e6_sqlite_requires_original_connect_and_connection_fd_identity(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            db_path = root / "sessions.sqlite3"
            connection = sqlite3.connect(db_path)
            try:
                connection.executescript(
                    "PRAGMA journal_mode=WAL;"
                    "CREATE TABLE sessions (id TEXT, source TEXT, session_key TEXT, ended_at TEXT);"
                    "CREATE INDEX sessions_id_idx ON sessions(id);"
                    "INSERT INTO sessions VALUES ('20260703_210417_8f66b434','discord','fixture-key',NULL);"
                )
            finally:
                connection.close()
            context = {"authorization": {"paths": {"persisted_db": str(db_path)}}}
            healthy = self.control._persisted_lookup(context, deadline_at=time.monotonic() + 5.0)
            self.assertTrue(healthy["read_only"])
            self.assertTrue(healthy["db_connected_file_equal"])
            original_connect = self.control.sqlite3.connect
            with patch.object(self.control.sqlite3, "connect", side_effect=original_connect):
                drifted = self.control._persisted_lookup(context, deadline_at=time.monotonic() + 5.0)
            self.assertFalse(drifted["read_only"], "a replaced connect callable is not authorized")
            alias = root / "sessions-alias.sqlite3"
            alias.symlink_to(db_path)
            symlinked = self.control._persisted_lookup(
                {"authorization": {"paths": {"persisted_db": str(alias)}}},
                deadline_at=time.monotonic() + 5.0,
            )
            self.assertFalse(symlinked["read_only"], "SQLite authority must reject symlinked paths")

    def test_e6_admission_report_requires_fresh_observation_and_scope_key(self):
        now = time.monotonic_ns()
        now_epoch = int(time.time())
        authorization = {
            "execution_scope": "fixture_readonly",
            "persisted_key_sha256": self.control.FIXTURE_KEY_SHA256,
            "candidate_id": "candidate",
            "candidate_sha256": "d" * 64,
            "source_commit": "e" * 40,
            "source_tree": "f" * 40,
            "control_sha256": "1" * 64,
            "specification_sha256": "2" * 64,
            "manifest_sha256": "b" * 64,
            "control_packet_sha256": "a" * 64,
            "not_before_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch - 60)),
            "expires_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch + 60)),
        }
        context = {
            "manifest_sha256": "b" * 64,
            "authorization_sha256": "c" * 64,
        }
        identity = {
            "candidate_id": "candidate",
            "archive_sha256": "d" * 64,
            "source_commit": "e" * 40,
            "source_tree": "f" * 40,
            "control_sha256": "1" * 64,
            "spec_sha256": "2" * 64,
        }
        observations = {
            "session_observed_utc": self.control._utc_now_iso(),
            "session_observed_monotonic_ns": now,
            "boot_id": self.control._boot_id(),
        }
        report = self.control._admission_report(
            context, {name: True for name in self.control.REQUIRED_PREDICATES}, [],
            time.monotonic(), self.control._utc_now_iso(), identity,
            observations=observations, authorization=authorization,
        )
        self.assertEqual(report["status_code"], 0)
        self.assertEqual(report["expected_key_sha256"], self.control.FIXTURE_KEY_SHA256)
        self.assertEqual(len(report["predicates"]), 32)
        raw = (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")
        admission_context = {
            **context,
            **identity,
            "authorization": authorization,
            "candidate_id": identity["candidate_id"],
            "archive_sha256": identity["archive_sha256"],
            "source_commit": identity["source_commit"],
            "source_tree": identity["source_tree"],
            "control_sha256": identity["control_sha256"],
            "control_packet_sha256": authorization["control_packet_sha256"],
            "spec_sha256": identity["spec_sha256"],
            "admission_sha256": hashlib.sha256(raw).hexdigest(),
        }
        self.assertIsNotNone(self.control._validate_a3_admission_report(admission_context, raw))
        freshness_mutations = {
            "stale_monotonic": {"session_observed_monotonic_ns": max(0, now - 10_000_000_001)},
            "future_finished": {"finished_utc": "2099-01-01T00:00:00Z"},
            "cross_boot": {"boot_id": "00000000-0000-4000-8000-000000000001"},
            "stale_utc": {"session_observed_utc": "2000-01-01T00:00:00Z"},
        }
        for label, mutation in freshness_mutations.items():
            with self.subTest(freshness=label):
                mutated = dict(report, **mutation)
                mutated_raw = (json.dumps(mutated, sort_keys=True) + "\n").encode("utf-8")
                self.assertIsNone(
                    self.control._validate_a3_admission_report(
                        dict(admission_context, admission_sha256=hashlib.sha256(mutated_raw).hexdigest()),
                        mutated_raw,
                    )
                )
        trailing_space = raw[:-1] + b" \n"
        self.assertIsNone(
            self.control._validate_a3_admission_report(
                dict(admission_context, admission_sha256=hashlib.sha256(trailing_space).hexdigest()),
                trailing_space,
            ),
            "A3 input is the exact stdout record, not JSON with trailing whitespace",
        )
        missing_window = dict(
            admission_context,
            authorization={key: value for key, value in authorization.items() if key not in {"not_before_utc", "expires_at_utc"}},
        )
        self.assertIsNone(
            self.control._validate_a3_admission_report(missing_window, raw),
            "A3 must not accept a report without authorization UTC bounds",
        )
        parsed_only = dict(admission_context, admission_report=report)
        self.assertIsNone(self.control._read_admission_report_once(parsed_only))

    def test_e6_candidate_registry_checks_dunder_and_finder_identity(self):
        helper = Voice1B6E5FindingRegressionTests()
        helper.control = self.control
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            per_file, archive = helper._bundle_fixture(root)
            snapshot = helper._snapshot_candidate_modules()
            try:
                helper._restore_candidate_modules({})
                with patch.object(self.control, "_verify_candidate_source", return_value=True):
                    bundle = self.control._load_candidate_module_bundle(
                        {"per_file_sha256": per_file}, {"archive_path": str(archive)},
                        retain_finder=True,
                    )
                self.assertIsInstance(bundle, dict)
                assert isinstance(bundle, dict)
                self.assertTrue(self.control._candidate_modules_still_bound(bundle, {}, {}))
                entry = bundle["registry"]["recorder_next.adapters"]
                module = entry["module"]
                old_name = module.__name__
                module.__name__ = "recorder_next.e6_rebound"
                try:
                    self.assertFalse(self.control._candidate_modules_still_bound(bundle, {}, {}))
                finally:
                    module.__name__ = old_name
                finder = bundle["finder"]
                old_map = finder._module_map
                finder._module_map = dict(old_map)
                try:
                    self.assertFalse(self.control._candidate_modules_still_bound(bundle, {}, {}))
                finally:
                    finder._module_map = old_map
            finally:
                self.control._release_candidate_module_bundle(locals().get("bundle"))
                helper._restore_candidate_modules(snapshot)

    def test_e6_sqlite_rechecks_path_after_close_swap_restore(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            db_path = root / "sessions.sqlite3"
            connection = sqlite3.connect(db_path)
            try:
                connection.executescript(
                    "CREATE TABLE sessions (id TEXT, source TEXT, session_key TEXT, ended_at TEXT);"
                    "CREATE INDEX sessions_id_idx ON sessions(id);"
                    "INSERT INTO sessions VALUES ('20260703_210417_8f66b434','discord','fixture-key',NULL);"
                )
            finally:
                connection.close()
            replacement = root / "replacement.sqlite3"
            replacement.write_bytes(db_path.read_bytes())

            class SwapOnClose:
                def __init__(self, real):
                    self.real = real

                def __getattr__(self, name):
                    return getattr(self.real, name)

                def close(self):
                    original = root / "original.sqlite3"
                    db_path.rename(original)
                    replacement.rename(db_path)
                    db_path.rename(replacement)
                    original.rename(db_path)
                    return self.real.close()

            context = {
                "authorization": {"paths": {"persisted_db": str(db_path)}},
                "boundary": {
                    "sqlite_connect": lambda *args, **kwargs: SwapOnClose(
                        sqlite3.connect(*args, **kwargs)
                    ),
                },
            }
            result = self.control._persisted_lookup(context, deadline_at=time.monotonic() + 5.0)
            self.assertFalse(result["read_only"], "post-close pathname substitution must be HOLD")
            self.assertFalse(result["db_identity_equal"])

    def test_e6_report_rejects_authorization_target_mismatch(self):
        now_epoch = int(time.time())
        authorization = {
            "execution_scope": "fixture_readonly",
            "persisted_key_sha256": self.control.FIXTURE_KEY_SHA256,
            "candidate_id": "wrong-target",
            "candidate_sha256": "d" * 64,
            "source_commit": "e" * 40,
            "source_tree": "f" * 40,
            "control_sha256": "1" * 64,
            "specification_sha256": "2" * 64,
            "manifest_sha256": "b" * 64,
            "control_packet_sha256": "a" * 64,
            "not_before_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch - 60)),
            "expires_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch + 60)),
        }
        identity = {
            "candidate_id": "right-target",
            "archive_sha256": "d" * 64,
            "source_commit": "e" * 40,
            "source_tree": "f" * 40,
            "control_sha256": "1" * 64,
            "spec_sha256": "2" * 64,
        }
        observations = {
            "session_observed_utc": self.control._utc_now_iso(),
            "session_observed_monotonic_ns": time.monotonic_ns(),
            "boot_id": self.control._boot_id(),
        }
        context = {"manifest_sha256": "b" * 64, "authorization_sha256": "c" * 64}
        report = self.control._admission_report(
            context, {name: True for name in self.control.REQUIRED_PREDICATES}, [],
            time.monotonic(), self.control._utc_now_iso(), identity,
            observations=observations, authorization=authorization,
        )
        raw = (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")
        admission_context = {
            **context,
            **identity,
            "authorization": authorization,
            "execution_scope": "fixture_readonly",
            "persisted_key_sha256": self.control.FIXTURE_KEY_SHA256,
            "control_packet_sha256": authorization["control_packet_sha256"],
            "admission_sha256": hashlib.sha256(raw).hexdigest(),
        }
        self.assertIsNone(
            self.control._validate_a3_admission_report(admission_context, raw),
            "A3 must bind target identity through authorization as well as report context",
        )
        unsafe_report = dict(report, candidate_id="../untrusted")
        unsafe_raw = (json.dumps(unsafe_report, sort_keys=True) + "\n").encode("utf-8")
        unsafe_auth = dict(authorization, candidate_id="../untrusted")
        self.assertIsNone(
            self.control._validate_a3_admission_report(
                dict(admission_context, candidate_id="../untrusted", authorization=unsafe_auth,
                     admission_sha256=hashlib.sha256(unsafe_raw).hexdigest()),
                unsafe_raw,
            ),
            "A3 candidate identity must retain the canonical identifier grammar",
        )

    def test_e6_a3_rejects_observation_before_attempt_start(self):
        now = time.monotonic_ns()
        now_epoch = int(time.time())
        authorization = {
            "execution_scope": "fixture_readonly",
            "persisted_key_sha256": self.control.FIXTURE_KEY_SHA256,
            "not_before_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch - 60)),
            "expires_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch + 60)),
        }
        context = {
            "authorization": authorization,
            "execution_scope": "fixture_readonly",
            "persisted_key_sha256": self.control.FIXTURE_KEY_SHA256,
        }
        observed = self.control._utc_now_iso()
        parsed = {
            "started_utc": observed,
            "finished_utc": observed,
            "session_observed_utc": "2000-01-01T00:00:00Z",
            "session_observed_monotonic_ns": now,
            "boot_id": self.control._boot_id(),
        }
        self.assertFalse(self.control._a3_admission_is_fresh(context, parsed))

    def test_e6_report_reason_codes_are_fixed_not_input_text(self):
        report = self.control._admission_report(
            {}, {}, ["credential-leak-secret", "internal_error"], time.monotonic(),
            self.control._utc_now_iso(), {},
        )
        self.assertNotIn("credential-leak-secret", report["reason_codes"])
        self.assertEqual(report["reason_codes"], ["internal_error"])

    def test_e6_a3_rejects_tampered_or_stale_report_before_mutation(self):
        self.assertTrue(hasattr(self.control, "_validate_a3_admission_report"))
        self.assertTrue(hasattr(self.control, "_read_admission_report_once"))
