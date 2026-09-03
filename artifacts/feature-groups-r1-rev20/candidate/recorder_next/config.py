from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


PROVIDER_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
PROVIDER_ADAPTERS = {
    "hermes",
    "hermes-default",
    "http",
    "http-asr",
    "http-tts",
    "openai-compatible",
    "nemotron",
    "whisper",
    "whisper-compatible",
    "edge",
    "edge-tts",
    "disabled",
    "none",
    "off",
    "fixture",
    "static",
    "test",
}
ASR_ADAPTERS = {
    "hermes",
    "hermes-default",
    "http",
    "http-asr",
    "openai-compatible",
    "nemotron",
    "whisper",
    "whisper-compatible",
    "fixture",
    "static",
    "test",
}
TTS_ADAPTERS = {
    "hermes",
    "hermes-default",
    "http",
    "http-tts",
    "openai-compatible",
    "edge",
    "edge-tts",
    "fixture",
    "static",
    "test",
}
DISABLED_ADAPTERS = {"", "disabled", "none", "off"}


@dataclass(frozen=True)
class ProviderConfig:
    """Redaction-safe declaration for one configured ASR or TTS target."""

    name: str
    kind: str
    adapter: str
    endpoint: str | None = None
    model: str | None = None
    voice: str | None = None
    language: str = "ko-KR"
    profile: str = "default"
    credential_file: str | None = None
    enabled: bool = True
    retries: int = 0
    timeout_seconds: float = 10.0
    fallback_of: str | None = None
    health_path: str | None = None
    capability_path: str | None = None
    max_bytes: int | None = None
    media_types: tuple[str, ...] = ()
    priority: int = 0
    rate: float | None = None
    pitch: float | None = None
    volume: float | None = None
    output_format: str | None = None
    options: tuple[tuple[str, str], ...] = ()

    @property
    def adapter_kind(self) -> str:
        return self.adapter

    @classmethod
    def from_spec(cls, name: str, kind: str, spec: Any) -> "ProviderConfig":
        if not isinstance(name, str) or not PROVIDER_NAME_RE.fullmatch(name):
            raise ValueError("provider name must be a bounded identifier")
        if kind not in {"asr", "tts"}:
            raise ValueError("provider kind must be asr or tts")
        if isinstance(spec, str):
            spec = {"adapter": spec}
        if not isinstance(spec, Mapping):
            raise ValueError("provider declaration must be a table")
        forbidden = {"api_key", "authorization", "password", "secret", "token", "inline_key", "credential"}
        if forbidden.intersection(str(key).lower() for key in spec):
            raise ValueError("inline provider secrets are not allowed")
        adapter = str(spec.get("adapter", spec.get("provider", spec.get("type", "disabled")))).strip().lower()
        if adapter not in PROVIDER_ADAPTERS:
            raise ValueError("unsupported provider adapter")
        endpoint = spec.get("endpoint", spec.get("url"))
        if endpoint is not None:
            endpoint = str(endpoint)
            if len(endpoint) > 512 or not endpoint.startswith(("http://", "https://")):
                raise ValueError("provider endpoint must use HTTP or HTTPS")
            parsed = endpoint.split("?", 1)
            if len(parsed) == 2 and any(part.split("=", 1)[0].lower() in {"key", "token", "secret", "password", "authorization"} for part in parsed[1].split("&") if "=" in part):
                raise ValueError("provider endpoint contains credentials")
        credential_file = spec.get("credential_file")
        if credential_file is not None:
            credential_file = str(credential_file)
            if (
                not credential_file
                or len(credential_file) > 512
                or any(ord(char) < 0x20 for char in credential_file)
                or re.search(r"(?:api[_-]?key|token|secret|password|authorization)\s*=", credential_file, re.I)
            ):
                raise ValueError("provider credential_file must be a reference, not an inline secret")
        retries = spec.get("retries", 0)
        timeout = spec.get("timeout_seconds", spec.get("timeout", 10.0))
        if not isinstance(retries, int) or isinstance(retries, bool) or not 0 <= retries <= 10:
            raise ValueError("provider retries must be between 0 and 10")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < float(timeout) <= 300:
            raise ValueError("provider timeout must be between 0 and 300 seconds")
        enabled = spec.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("provider enabled must be boolean")
        media_raw = spec.get("media_types", spec.get("accepted_media_types", ()))
        if isinstance(media_raw, str):
            media_raw = (media_raw,)
        if not isinstance(media_raw, Sequence) or isinstance(media_raw, (bytes, bytearray)):
            raise ValueError("provider media_types must be a string array")
        media_types = tuple(str(item).lower() for item in media_raw)
        if any(not re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+*-]+", item) for item in media_types):
            raise ValueError("provider media type is invalid")
        max_bytes = spec.get("max_bytes", spec.get("media_max_bytes"))
        if max_bytes is not None and (not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= 1024 * 1024 * 1024):
            raise ValueError("provider max_bytes is invalid")
        priority = spec.get("priority", 0)
        if not isinstance(priority, int) or isinstance(priority, bool) or not -10000 <= priority <= 10000:
            raise ValueError("provider priority is invalid")
        numeric_controls: dict[str, float | None] = {}
        for control in ("rate", "pitch", "volume"):
            value = spec.get(control)
            if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool) or not -1000 <= float(value) <= 1000):
                raise ValueError(f"provider {control} is invalid")
            numeric_controls[control] = float(value) if value is not None else None
        output_format = spec.get("output_format", spec.get("format"))
        if output_format is not None and (not isinstance(output_format, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", output_format)):
            raise ValueError("provider output_format is invalid")
        options_raw = spec.get("options", {})
        if not isinstance(options_raw, Mapping):
            raise ValueError("provider options must be a table")
        options: list[tuple[str, str]] = []
        for option_key, option_value in options_raw.items():
            if not isinstance(option_key, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", option_key) or str(option_key).lower() in forbidden:
                raise ValueError("provider option name is invalid")
            if not isinstance(option_value, (str, int, float, bool)) or isinstance(option_value, (bytes, bytearray)):
                raise ValueError("provider option must be scalar")
            options.append((option_key, str(option_value)))
        health_path = spec.get("health_path", spec.get("health_probe"))
        capability_path = spec.get("capability_path", spec.get("capability_probe"))
        for path_value in (health_path, capability_path):
            if path_value is not None and (not isinstance(path_value, str) or not path_value.startswith("/") or len(path_value) > 256 or any(ord(char) < 0x20 for char in path_value)):
                raise ValueError("provider probe path is invalid")
        return cls(
            name=name,
            kind=kind,
            adapter=adapter,
            endpoint=endpoint,
            model=str(spec["model"]) if spec.get("model") is not None else None,
            voice=str(spec["voice"]) if spec.get("voice") is not None else None,
            language=str(spec.get("language", "ko-KR")),
            profile=str(spec.get("profile", "default")),
            credential_file=credential_file,
            enabled=enabled,
            retries=retries,
            timeout_seconds=float(timeout),
            fallback_of=str(spec["fallback_of"]) if spec.get("fallback_of") is not None else None,
            health_path=health_path,
            capability_path=capability_path,
            max_bytes=max_bytes,
            media_types=media_types,
            priority=priority,
            rate=numeric_controls["rate"],
            pitch=numeric_controls["pitch"],
            volume=numeric_controls["volume"],
            output_format=str(output_format) if output_format is not None else None,
            options=tuple(sorted(options)),
        )

    def resolved(self, base_dir: str | os.PathLike[str]) -> "ProviderConfig":
        if self.credential_file is None:
            return self
        candidate = Path(os.path.expanduser(os.path.expandvars(self.credential_file)))
        if not candidate.is_absolute():
            candidate = Path(base_dir) / candidate
        return replace(self, credential_file=str(candidate))

    def safe_dict(self) -> dict[str, Any]:
        if not PROVIDER_NAME_RE.fullmatch(self.name) or self.kind not in {"asr", "tts"}:
            raise ValueError("provider declaration is invalid")
        if self.adapter not in PROVIDER_ADAPTERS:
            raise ValueError("provider adapter is invalid")
        allowed_adapters = ASR_ADAPTERS if self.kind == "asr" else TTS_ADAPTERS
        if self.adapter not in allowed_adapters:
            raise ValueError("provider adapter does not match provider kind")
        if not isinstance(self.enabled, bool):
            raise ValueError("provider enabled must be boolean")
        if not isinstance(self.retries, int) or isinstance(self.retries, bool) or not 0 <= self.retries <= 10:
            raise ValueError("provider retries must be between 0 and 10")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) or not 0 < float(self.timeout_seconds) <= 300:
            raise ValueError("provider timeout must be between 0 and 300 seconds")
        if not isinstance(self.priority, int) or isinstance(self.priority, bool) or not -10000 <= self.priority <= 10000:
            raise ValueError("provider priority is invalid")
        if self.credential_file is not None and (
            not isinstance(self.credential_file, str)
            or not self.credential_file
            or len(self.credential_file) > 512
            or any(ord(char) < 0x20 for char in self.credential_file)
            or re.search(r"(?:api[_-]?key|token|secret|password|authorization)\s*=", self.credential_file, re.I)
        ):
            raise ValueError("provider credential_file must be a reference")
        if self.language and (not isinstance(self.language, str) or len(self.language) > 32 or any(ord(char) < 0x20 for char in self.language)):
            raise ValueError("provider language is invalid")
        if self.profile and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.profile):
            raise ValueError("provider profile is invalid")
        result: dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
            "adapter": self.adapter,
            "enabled": self.enabled,
            "retries": self.retries,
            "timeout_seconds": self.timeout_seconds,
            "credential_configured": bool(self.credential_file),
            "priority": self.priority,
        }
        if self.credential_file:
            # The reference itself is sensitive deployment metadata.  Bind
            # generation changes to an opaque digest without persisting it.
            result["credential_ref_sha256"] = hashlib.sha256(self.credential_file.encode("utf-8")).hexdigest()
        for key in ("endpoint", "model", "voice", "language", "profile", "fallback_of", "health_path", "capability_path"):
            value = getattr(self, key)
            if value is not None:
                if not isinstance(value, str) or len(value) > 512 or any(ord(char) < 0x20 for char in value):
                    raise ValueError("provider scalar configuration is invalid")
                if key == "endpoint":
                    parsed_endpoint = urlsplit(value)
                    if parsed_endpoint.scheme not in {"http", "https"} or not parsed_endpoint.netloc or parsed_endpoint.fragment or parsed_endpoint.username or parsed_endpoint.password or any(
                        item.split("=", 1)[0].lower() in {"key", "token", "secret", "password", "authorization"}
                        for item in parsed_endpoint.query.split("&")
                        if "=" in item
                    ) or any(item.split("=", 1)[0].lower() != "profile" for item in parsed_endpoint.query.split("&") if item):
                        raise ValueError("provider endpoint contains credentials")
                if key in {"health_path", "capability_path"} and (
                    not value.startswith("/")
                    or urlsplit(value).scheme
                    or urlsplit(value).netloc
                    or urlsplit(value).query
                    or urlsplit(value).fragment
                ):
                    raise ValueError("provider probe path is invalid")
                result[key] = value
        if self.max_bytes is not None:
            if not isinstance(self.max_bytes, int) or isinstance(self.max_bytes, bool) or not 1 <= self.max_bytes <= 1024 * 1024 * 1024:
                raise ValueError("provider max_bytes is invalid")
            result["max_bytes"] = self.max_bytes
        if self.media_types:
            result["media_types"] = list(self.media_types)
        for key in ("rate", "pitch", "volume", "output_format"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        if self.options:
            result["options"] = {key: value for key, value in self.options}
        return result


@dataclass(frozen=True)
class RecorderConfig:
    host: str = "127.0.0.1"
    port: int = 8643
    database: str = "./state/recorder-next.sqlite3"
    storage_root: str = "./state/data"
    min_free_bytes: int = 0
    max_audio_minutes: int = 120
    max_audio_bytes: int = 1024 * 1024 * 1024
    max_chunk_bytes: int = 1024 * 1024
    max_text_bytes: int = 10 * 1024 * 1024
    max_attachment_bytes: int = 250 * 1024 * 1024
    max_turn_bytes: int = 1024 * 1024 * 1024
    max_parts: int = 20
    hermes_max_attempts: int = 2
    hermes_grace_seconds: int = 30
    asr_provider_timeout_seconds: int = 10
    tts_retry_seconds: int = 10
    hermes_base_url: str | None = None
    hermes_api_key_file: str | None = None
    hermes_profile: str = "default"
    asr_source: str = "hermes"
    tts_source: str = "hermes"
    asr_mode: str | None = None
    tts_mode: str | None = None
    asr_fallback_source: str | None = None
    tts_fallback_source: str | None = None
    realtime_asr_provider: str = "hermes"
    realtime_asr_endpoint: str | None = None
    realtime_asr_model: str | None = None
    realtime_asr_credential_file: str | None = None
    batch_asr_provider: str = "disabled"
    batch_asr_endpoint: str | None = None
    batch_asr_model: str | None = None
    batch_asr_credential_file: str | None = None
    local_asr_provider: str = "disabled"
    local_asr_endpoint: str | None = None
    local_asr_model: str | None = None
    local_asr_credential_file: str | None = None
    tts_provider: str = "hermes"
    tts_endpoint: str | None = None
    tts_model: str | None = None
    tts_voice: str | None = None
    tts_credential_file: str | None = None
    tts_timeout_seconds: int = 10
    tts_artifact_ttl_seconds: int = 86400
    diagnostics_max_compressed_bytes: int = 2 * 1024 * 1024
    diagnostics_max_expanded_bytes: int = 16 * 1024 * 1024
    diagnostics_retention_seconds: int = 7 * 86400
    asr_providers: tuple[ProviderConfig, ...] = ()
    tts_providers: tuple[ProviderConfig, ...] = ()
    asr_chain: tuple[str, ...] = ()
    tts_chain: tuple[str, ...] = ()
    asr_deadline_seconds: float = 60.0
    tts_deadline_seconds: float = 60.0
    asr_fallback_order: tuple[str, ...] = ()
    asr_overrides: tuple[tuple[str, tuple[str, ...]], ...] = ()
    tts_overrides: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        for field_name, kind in (("asr_providers", "asr"), ("tts_providers", "tts")):
            values = getattr(self, field_name)
            if isinstance(values, Mapping):
                values = tuple(ProviderConfig.from_spec(str(name), kind, spec) for name, spec in values.items())
            else:
                values = tuple(value if isinstance(value, ProviderConfig) else ProviderConfig.from_spec(str(value.get("name", f"{kind}-{index + 1}")), kind, value) for index, value in enumerate(values))
            object.__setattr__(self, field_name, values)
        def normalize_chain(value: Any, kind: str) -> tuple[str, ...]:
            raw = (value,) if isinstance(value, str) else tuple(value)
            return tuple(item.split(":", 1)[1] if isinstance(item, str) and item.startswith(f"{kind}:") else str(item) for item in raw)

        def normalize_overrides(value: Any, kind: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
            items = value.items() if isinstance(value, Mapping) else value
            return tuple((str(scope), normalize_chain(chain, kind)) for scope, chain in items)

        object.__setattr__(self, "asr_chain", normalize_chain(self.asr_chain, "asr"))
        object.__setattr__(self, "tts_chain", normalize_chain(self.tts_chain, "tts"))
        object.__setattr__(self, "asr_overrides", normalize_overrides(self.asr_overrides, "asr"))
        object.__setattr__(self, "tts_overrides", normalize_overrides(self.tts_overrides, "tts"))

        def materialize_primary(kind: str, source: str, endpoint: str | None, model: str | None, voice: str | None, credential: str | None) -> None:
            providers_field = "asr_providers" if kind == "asr" else "tts_providers"
            chain_field = "asr_chain" if kind == "asr" else "tts_chain"
            if getattr(self, providers_field) or getattr(self, chain_field) or not endpoint:
                return
            if source.lower() == "hermes" and not credential:
                return
            if source.lower() not in (ASR_ADAPTERS if kind == "asr" else TTS_ADAPTERS):
                return
            spec: dict[str, Any] = {"adapter": source, "endpoint": endpoint, "enabled": True}
            if model is not None:
                spec["model"] = model
            if voice is not None:
                spec["voice"] = voice
            if credential is not None:
                spec["credential_file"] = credential
            declaration = ProviderConfig.from_spec("primary", kind, spec)
            object.__setattr__(self, providers_field, (declaration,))
            object.__setattr__(self, chain_field, ("primary",))

        asr_primary_source = self.asr_mode or (self.asr_source if str(self.asr_source).lower() != "hermes" or self.realtime_asr_provider.strip().lower() == "hermes" else self.realtime_asr_provider)
        asr_primary_endpoint = self.hermes_base_url if str(asr_primary_source).lower() == "hermes" else self.realtime_asr_endpoint
        asr_primary_credential = self.hermes_api_key_file if str(asr_primary_source).lower() == "hermes" else self.realtime_asr_credential_file
        materialize_primary("asr", str(asr_primary_source), asr_primary_endpoint, self.realtime_asr_model, None, asr_primary_credential)
        tts_primary_source = self.tts_mode or (self.tts_source if str(self.tts_source).lower() != "hermes" or self.tts_provider.strip().lower() == "hermes" else self.tts_provider)
        tts_primary_endpoint = self.hermes_base_url if str(tts_primary_source).lower() == "hermes" else self.tts_endpoint
        tts_primary_credential = self.hermes_api_key_file if str(tts_primary_source).lower() == "hermes" else self.tts_credential_file
        materialize_primary("tts", str(tts_primary_source), tts_primary_endpoint, self.tts_model, self.tts_voice, tts_primary_credential)

    @staticmethod
    def _registry(providers: Mapping[str, Any], kind: str) -> tuple[tuple[ProviderConfig, ...], tuple[str, ...], float]:
        """Parse both ``providers.asr`` tables and array-of-table registries."""
        raw = providers.get(f"{kind}_providers")
        if raw is None:
            raw = providers.get(kind)
        declarations: list[ProviderConfig] = []
        explicit_chain: Any = providers.get(f"{kind}_chain")
        deadline_raw: Any = providers.get(f"{kind}_deadline_seconds", 60.0)
        if isinstance(raw, Mapping):
            if explicit_chain is None:
                explicit_chain = raw.get("chain", raw.get("order"))
            deadline_raw = raw.get("deadline_seconds", deadline_raw)
            # A direct [providers.asr] table is also a valid one-target
            # declaration.  Otherwise each nested key is a named target.
            if any(key in raw for key in ("adapter", "provider", "type")):
                declarations.append(ProviderConfig.from_spec("default", kind, raw))
            else:
                for name, spec in raw.items():
                    if name in {"chain", "fallback", "fallback_order", "deadline_seconds"}:
                        continue
                    declarations.append(ProviderConfig.from_spec(str(name), kind, spec))
        elif isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
            for index, item in enumerate(raw):
                if not isinstance(item, Mapping):
                    raise ValueError(f"{kind} provider array entries must be tables")
                name = item.get("name", f"{kind}-{index + 1}")
                declarations.append(ProviderConfig.from_spec(str(name), kind, item))
        elif raw is not None:
            if isinstance(raw, str):
                declarations.append(
                    ProviderConfig.from_spec(
                        "default",
                        kind,
                        {
                            "adapter": raw,
                            "endpoint": providers.get(f"{kind}_endpoint"),
                            "model": providers.get(f"{kind}_model"),
                            "voice": providers.get(f"{kind}_voice"),
                            "credential_file": providers.get(f"{kind}_credential_file"),
                        },
                    )
                )
            else:
                declarations.append(ProviderConfig.from_spec("default", kind, raw))
        elif explicit_chain is None and str(providers.get(f"{kind}_source", providers.get(f"{kind}_mode", "hermes"))).lower() == "hermes":
            # The inherited Hermes profile is the only implicit primary.  A
            # Recorder-owned target is never discovered merely because its
            # declaration is present; it must appear in an explicit chain.
            hermes_base_url = providers.get("hermes_base_url")
            hermes_credential = providers.get("hermes_api_key_file")
            if hermes_base_url and hermes_credential:
                declarations.append(
                    ProviderConfig.from_spec(
                        "hermes-default",
                        kind,
                        {
                            "adapter": "hermes",
                            "endpoint": hermes_base_url,
                            "profile": providers.get("hermes_profile", "default"),
                            "credential_file": hermes_credential,
                            "enabled": True,
                        },
                    )
                )
                explicit_chain = ("hermes-default",)
        names = {item.name for item in declarations}
        if len(names) != len(declarations):
            raise ValueError(f"duplicate {kind} provider names")
        for item in declarations:
            if item.fallback_of is not None and item.fallback_of not in names:
                raise ValueError(f"{kind} fallback target is missing")
        if explicit_chain is None:
            # An empty selection is intentional: it is the safe default for a
            # registry with no reviewed primary/fallback order.
            chain = ()
        elif isinstance(explicit_chain, str):
            chain = (explicit_chain,)
        elif isinstance(explicit_chain, Sequence) and not isinstance(explicit_chain, (bytes, bytearray)):
            chain = tuple(str(item) for item in explicit_chain)
        else:
            raise ValueError(f"{kind}_chain must be a string array")
        normalized_chain = tuple(item.split(":", 1)[1] if item.startswith(f"{kind}:") else item for item in chain)
        if any(not PROVIDER_NAME_RE.fullmatch(item) for item in normalized_chain):
            raise ValueError(f"{kind}_chain contains an invalid provider name")
        if len(set(normalized_chain)) != len(normalized_chain):
            raise ValueError(f"{kind}_chain contains duplicates")
        if declarations and any(item not in names for item in normalized_chain):
            raise ValueError(f"{kind}_chain refers to an unknown provider")
        if not isinstance(deadline_raw, (int, float)) or isinstance(deadline_raw, bool) or not 0 < float(deadline_raw) <= 1800:
            raise ValueError(f"{kind}_deadline_seconds must be between 0 and 1800")
        return tuple(declarations), normalized_chain, float(deadline_raw)

    @staticmethod
    def _overrides(providers: Mapping[str, Any], kind: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
        raw: Any = providers.get(f"{kind}_overrides")
        if raw is None:
            all_overrides = providers.get("overrides", {})
            raw = all_overrides if isinstance(all_overrides, Mapping) else {}
        entries: list[tuple[str, tuple[str, ...]]] = []

        def add(scope: str, spec: Any) -> None:
            if not PROVIDER_NAME_RE.fullmatch(scope.replace(":", "_")):
                raise ValueError("provider override scope is invalid")
            if not isinstance(spec, Mapping):
                raise ValueError("provider override must be a table")
            chain_raw = spec.get(f"{kind}_chain", spec.get(kind))
            if chain_raw is None:
                return
            if isinstance(chain_raw, str):
                chain = (chain_raw,)
            elif isinstance(chain_raw, Sequence) and not isinstance(chain_raw, (bytes, bytearray)):
                chain = tuple(str(item) for item in chain_raw)
            else:
                raise ValueError("provider override chain must be a string array")
            normalized = tuple(item.split(":", 1)[1] if item.startswith(f"{kind}:") else item for item in chain)
            if not normalized or len(set(normalized)) != len(normalized) or any(not PROVIDER_NAME_RE.fullmatch(item) for item in normalized):
                raise ValueError("provider override chain is invalid")
            entries.append((scope, normalized))

        if isinstance(raw, Mapping):
            # Direct form: {"project:P": {"asr_chain": [...]}}
            if any(key.endswith("_chain") or key in {"asr", "tts"} for key in raw):
                add("global", raw)
            else:
                for scope_group, group in raw.items():
                    if isinstance(group, Mapping) and any(key.endswith("_chain") for key in group):
                        add(str(scope_group), group)
                    elif isinstance(group, Mapping):
                        for scope_name, spec in group.items():
                            add(f"{scope_group}:{scope_name}", spec)
        elif raw is not None:
            raise ValueError("provider overrides must be a table")
        return tuple(entries)

    @staticmethod
    def _provider_values(providers: Mapping[str, Any], name: str, default: str = "disabled") -> tuple[str, str | None, str | None, str | None]:
        raw = providers.get(name, default)
        section = raw if isinstance(raw, dict) else {}
        provider = str(section.get("provider", raw if isinstance(raw, str) else "disabled"))
        endpoint = section.get("endpoint") or providers.get(f"{name}_endpoint") or providers.get(f"{name}_url")
        model = section.get("model") or providers.get(f"{name}_model")
        credential = section.get("credential_file") or providers.get(f"{name}_credential_file")
        return provider, (str(endpoint) if endpoint is not None else None), (str(model) if model is not None else None), (str(credential) if credential is not None else None)

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "RecorderConfig":
        path = Path(path)
        with path.open("rb") as handle:
            data: dict[str, Any] = tomllib.load(handle)
        server = data.get("server", {})
        storage = data.get("storage", {})
        limits = data.get("limits", {})
        retries = data.get("retries", {})
        providers = data.get("providers", {})
        if not isinstance(providers, Mapping):
            raise ValueError("providers must be a TOML table")
        provider_values = dict(providers)
        if "hermes_api_key_file" not in provider_values and os.environ.get("RECORDER_NEXT_HERMES_API_KEY_FILE"):
            provider_values["hermes_api_key_file"] = os.environ["RECORDER_NEXT_HERMES_API_KEY_FILE"]
        asr_registry, asr_chain, asr_deadline = cls._registry(provider_values, "asr")
        tts_registry, tts_chain, tts_deadline = cls._registry(provider_values, "tts")
        asr_overrides = cls._overrides(provider_values, "asr")
        tts_overrides = cls._overrides(provider_values, "tts")
        fallback_raw = provider_values.get("asr_fallback_order", cls.asr_fallback_order)
        if isinstance(fallback_raw, str):
            fallback_order = (fallback_raw,)
        elif isinstance(fallback_raw, Sequence) and not isinstance(fallback_raw, (bytes, bytearray)):
            fallback_order = tuple(str(item) for item in fallback_raw)
        else:
            raise ValueError("asr_fallback_order must be a string array")
        asr_source = str(providers.get("asr_source", providers.get("asr_mode", "hermes")))
        tts_source = str(providers.get("tts_source", providers.get("tts_mode", "hermes")))
        hermes_profile = str(providers.get("hermes_profile", "default"))
        realtime = cls._provider_values(providers, "realtime_asr", asr_source)
        batch = cls._provider_values(providers, "batch_asr")
        local = cls._provider_values(providers, "local_asr")
        tts_raw = providers.get("tts", tts_source)
        tts_section = tts_raw if isinstance(tts_raw, dict) else {}
        tts_provider = str(tts_section.get("provider", tts_raw if isinstance(tts_raw, str) else "disabled"))
        tts_endpoint = tts_section.get("endpoint") or providers.get("tts_endpoint") or providers.get("tts_url")
        tts_model = tts_section.get("model") or providers.get("tts_model")
        tts_voice = tts_section.get("voice") or providers.get("tts_voice")
        tts_credential = tts_section.get("credential_file") or providers.get("tts_credential_file")
        config = cls(
            host=str(server.get("host", cls.host)),
            port=int(server.get("port", cls.port)),
            database=str(storage.get("database", cls.database)),
            storage_root=str(storage.get("root", cls.storage_root)),
            min_free_bytes=int(storage.get("min_free_bytes", cls.min_free_bytes)),
            max_audio_minutes=int(limits.get("max_audio_minutes", cls.max_audio_minutes)),
            max_audio_bytes=int(limits.get("max_audio_bytes", cls.max_audio_bytes)),
            max_chunk_bytes=int(limits.get("max_chunk_bytes", cls.max_chunk_bytes)),
            max_text_bytes=int(limits.get("max_text_bytes", cls.max_text_bytes)),
            max_attachment_bytes=int(limits.get("max_attachment_bytes", cls.max_attachment_bytes)),
            max_turn_bytes=int(limits.get("max_turn_bytes", cls.max_turn_bytes)),
            max_parts=int(limits.get("max_parts", cls.max_parts)),
            hermes_max_attempts=int(retries.get("hermes_max_attempts", cls.hermes_max_attempts)),
            hermes_grace_seconds=int(retries.get("hermes_late_result_grace_seconds", cls.hermes_grace_seconds)),
            asr_provider_timeout_seconds=int(retries.get("asr_provider_timeout_seconds", cls.asr_provider_timeout_seconds)),
            tts_retry_seconds=int(retries.get("tts_retry_seconds", cls.tts_retry_seconds)),
            hermes_base_url=providers.get("hermes_base_url"),
            hermes_api_key_file=providers.get(
                "hermes_api_key_file", os.environ.get("RECORDER_NEXT_HERMES_API_KEY_FILE")
            ),
            hermes_profile=hermes_profile,
            asr_source=asr_source,
            tts_source=tts_source,
            asr_mode=providers.get("asr_mode"),
            tts_mode=providers.get("tts_mode"),
            asr_fallback_source=providers.get("asr_fallback_source"),
            tts_fallback_source=providers.get("tts_fallback_source"),
            realtime_asr_provider=realtime[0],
            realtime_asr_endpoint=realtime[1],
            realtime_asr_model=realtime[2],
            realtime_asr_credential_file=realtime[3],
            batch_asr_provider=batch[0],
            batch_asr_endpoint=batch[1],
            batch_asr_model=batch[2],
            batch_asr_credential_file=batch[3],
            local_asr_provider=local[0],
            local_asr_endpoint=local[1],
            local_asr_model=local[2],
            local_asr_credential_file=local[3],
            tts_provider=tts_provider,
            tts_endpoint=str(tts_endpoint) if tts_endpoint is not None else None,
            tts_model=str(tts_model) if tts_model is not None else None,
            tts_voice=str(tts_voice) if tts_voice is not None else None,
            tts_credential_file=str(tts_credential) if tts_credential is not None else None,
            tts_timeout_seconds=int(providers.get("tts_timeout_seconds", cls.tts_timeout_seconds)),
            tts_artifact_ttl_seconds=int(providers.get("tts_artifact_ttl_seconds", cls.tts_artifact_ttl_seconds)),
            diagnostics_max_compressed_bytes=int(limits.get("diagnostics_max_compressed_bytes", cls.diagnostics_max_compressed_bytes)),
            diagnostics_max_expanded_bytes=int(limits.get("diagnostics_max_expanded_bytes", cls.diagnostics_max_expanded_bytes)),
            diagnostics_retention_seconds=int(limits.get("diagnostics_retention_seconds", cls.diagnostics_retention_seconds)),
            asr_providers=asr_registry,
            tts_providers=tts_registry,
            asr_chain=asr_chain,
            tts_chain=tts_chain,
            asr_deadline_seconds=asr_deadline,
            tts_deadline_seconds=tts_deadline,
            asr_overrides=asr_overrides,
            tts_overrides=tts_overrides,
            asr_fallback_order=fallback_order,
        )
        config.validate()
        return config

    def validate(self) -> "RecorderConfig":
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("server port must be between 1 and 65535")
        if not isinstance(self.host, str) or not self.host or any(ord(char) < 0x20 for char in self.host):
            raise ValueError("server host is invalid")
        for field_name in ("asr_source", "tts_source", "asr_mode", "tts_mode"):
            value = getattr(self, field_name)
            if value is not None and (not isinstance(value, str) or not PROVIDER_NAME_RE.fullmatch(value)):
                raise ValueError(f"{field_name} is invalid")
        if not isinstance(self.hermes_profile, str) or not re.fullmatch(r"^[A-Za-z0-9_.-]{1,64}$", self.hermes_profile):
            raise ValueError("Hermes profile is invalid")
        if self.hermes_base_url is not None:
            if not isinstance(self.hermes_base_url, str) or len(self.hermes_base_url) > 512 or not self.hermes_base_url.startswith(("http://", "https://")):
                raise ValueError("Hermes endpoint is invalid")
            parsed = urlsplit(self.hermes_base_url)
            if parsed.username or parsed.password or parsed.fragment or any(part.split("=", 1)[0].lower() in {"key", "token", "secret", "password", "authorization"} for part in parsed.query.split("&") if "=" in part) or any(part.split("=", 1)[0].lower() != "profile" for part in parsed.query.split("&") if part):
                raise ValueError("Hermes endpoint contains credentials")
        for credential in (self.hermes_api_key_file, self.realtime_asr_credential_file, self.batch_asr_credential_file, self.local_asr_credential_file, self.tts_credential_file):
            if credential is not None and (not isinstance(credential, str) or not credential or any(ord(char) < 0x20 for char in credential) or re.search(r"(?:api[_-]?key|token|secret|password|authorization)\s*=", credential, re.I)):
                raise ValueError("credential configuration must be a file reference")
        if not isinstance(self.asr_deadline_seconds, (int, float)) or isinstance(self.asr_deadline_seconds, bool) or not 0 < float(self.asr_deadline_seconds) <= 1800:
            raise ValueError("ASR deadline is invalid")
        if not isinstance(self.tts_deadline_seconds, (int, float)) or isinstance(self.tts_deadline_seconds, bool) or not 0 < float(self.tts_deadline_seconds) <= 1800:
            raise ValueError("TTS deadline is invalid")
        if len(set(self.asr_fallback_order)) != len(self.asr_fallback_order) or any(item not in {"realtime", "batch", "local"} for item in self.asr_fallback_order):
            raise ValueError("ASR fallback order is invalid")
        asr_names = {item.name for item in self.asr_providers}
        tts_names = {item.name for item in self.tts_providers}
        if len(asr_names) != len(self.asr_providers) or len(tts_names) != len(self.tts_providers):
            raise ValueError("provider names must be unique")
        for item in (*self.asr_providers, *self.tts_providers):
            item.safe_dict()
        for declarations in (self.asr_providers, self.tts_providers):
            by_name = {item.name: item for item in declarations}
            for item in declarations:
                seen: set[str] = set()
                current = item
                while current.fallback_of is not None:
                    if current.name in seen:
                        raise ValueError("provider fallback graph contains a cycle")
                    seen.add(current.name)
                    parent = by_name.get(current.fallback_of)
                    if parent is None:
                        raise ValueError("provider fallback target is missing")
                    current = parent
        if any(name not in asr_names for name in self.asr_chain) or len(set(self.asr_chain)) != len(self.asr_chain):
            raise ValueError("ASR chain refers to an unknown or duplicate provider")
        if any(name not in tts_names for name in self.tts_chain) or len(set(self.tts_chain)) != len(self.tts_chain):
            raise ValueError("TTS chain refers to an unknown or duplicate provider")
        for kind, chain, declarations in (("ASR", self.asr_chain, self.asr_providers), ("TTS", self.tts_chain, self.tts_providers)):
            by_name = {item.name: item for item in declarations}
            for name in chain:
                item = by_name[name]
                if not item.enabled or item.adapter in DISABLED_ADAPTERS:
                    raise ValueError(f"{kind} chain includes a disabled provider")
        for kind, overrides, names in (("ASR", self.asr_overrides, asr_names), ("TTS", self.tts_overrides, tts_names)):
            seen_scopes: set[str] = set()
            for scope, chain in overrides:
                if scope in seen_scopes or not scope or len(scope) > 128 or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", scope):
                    raise ValueError(f"{kind} provider override scope is invalid")
                seen_scopes.add(scope)
                if not chain or len(set(chain)) != len(chain) or any(name not in names for name in chain):
                    raise ValueError(f"{kind} provider override refers to an unknown or duplicate provider")
        return self

    def safe_provider_config(self) -> dict[str, Any]:
        self.validate()
        return {
            "hermes_profile": self.hermes_profile,
            "asr_source": self.asr_source,
            "tts_source": self.tts_source,
            "asr_chain": list(self.asr_chain),
            "tts_chain": list(self.tts_chain),
            "asr_deadline_seconds": float(self.asr_deadline_seconds),
            "tts_deadline_seconds": float(self.tts_deadline_seconds),
            "asr_fallback_order": list(self.asr_fallback_order),
            "asr_providers": [item.safe_dict() for item in self.asr_providers],
            "tts_providers": [item.safe_dict() for item in self.tts_providers],
            "asr_overrides": {scope: list(chain) for scope, chain in self.asr_overrides},
            "tts_overrides": {scope: list(chain) for scope, chain in self.tts_overrides},
        }

    def provider_chain_names(self, kind: str, *scopes: str) -> tuple[str, ...]:
        """Return the explicit chain selected by the safest matching scope."""
        if kind not in {"asr", "tts"}:
            raise ValueError("provider kind must be asr or tts")
        overrides = dict(self.asr_overrides if kind == "asr" else self.tts_overrides)
        for scope in scopes:
            if not isinstance(scope, str):
                continue
            selected = overrides.get(scope)
            if selected is not None:
                return tuple(selected)
        selected = overrides.get("global")
        if selected is not None:
            return tuple(selected)
        return tuple(self.asr_chain if kind == "asr" else self.tts_chain)

    @property
    def provider_generation(self) -> str:
        encoded = json.dumps(self.safe_provider_config(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def resolved(self, *, base_dir: str | os.PathLike[str] = ".") -> "RecorderConfig":
        base = Path(base_dir)
        db = Path(self.database)
        root = Path(self.storage_root)
        credential = self.hermes_api_key_file
        if credential is not None:
            credential_path = Path(os.path.expanduser(os.path.expandvars(str(credential))))
            credential = str(credential_path if credential_path.is_absolute() else base / credential_path)
        def resolve_optional(value: str | None) -> str | None:
            if value is None:
                return None
            candidate = Path(os.path.expanduser(os.path.expandvars(value)))
            return str(candidate if candidate.is_absolute() else base / candidate)

        return RecorderConfig(
            host=self.host,
            port=self.port,
            database=str(db if db.is_absolute() else base / db),
            storage_root=str(root if root.is_absolute() else base / root),
            min_free_bytes=self.min_free_bytes,
            max_audio_minutes=self.max_audio_minutes,
            max_audio_bytes=self.max_audio_bytes,
            max_chunk_bytes=self.max_chunk_bytes,
            max_text_bytes=self.max_text_bytes,
            max_attachment_bytes=self.max_attachment_bytes,
            max_turn_bytes=self.max_turn_bytes,
            max_parts=self.max_parts,
            hermes_max_attempts=self.hermes_max_attempts,
            hermes_grace_seconds=self.hermes_grace_seconds,
            asr_provider_timeout_seconds=self.asr_provider_timeout_seconds,
            tts_retry_seconds=self.tts_retry_seconds,
            hermes_base_url=self.hermes_base_url,
            hermes_api_key_file=credential,
            hermes_profile=self.hermes_profile,
            asr_source=self.asr_source,
            tts_source=self.tts_source,
            asr_mode=self.asr_mode,
            tts_mode=self.tts_mode,
            asr_fallback_source=self.asr_fallback_source,
            tts_fallback_source=self.tts_fallback_source,
            realtime_asr_provider=self.realtime_asr_provider,
            realtime_asr_endpoint=self.realtime_asr_endpoint,
            realtime_asr_model=self.realtime_asr_model,
            realtime_asr_credential_file=resolve_optional(self.realtime_asr_credential_file),
            batch_asr_provider=self.batch_asr_provider,
            batch_asr_endpoint=self.batch_asr_endpoint,
            batch_asr_model=self.batch_asr_model,
            batch_asr_credential_file=resolve_optional(self.batch_asr_credential_file),
            local_asr_provider=self.local_asr_provider,
            local_asr_endpoint=self.local_asr_endpoint,
            local_asr_model=self.local_asr_model,
            local_asr_credential_file=resolve_optional(self.local_asr_credential_file),
            tts_provider=self.tts_provider,
            tts_endpoint=self.tts_endpoint,
            tts_model=self.tts_model,
            tts_voice=self.tts_voice,
            tts_credential_file=resolve_optional(self.tts_credential_file),
            tts_timeout_seconds=self.tts_timeout_seconds,
            tts_artifact_ttl_seconds=self.tts_artifact_ttl_seconds,
            diagnostics_max_compressed_bytes=self.diagnostics_max_compressed_bytes,
            diagnostics_max_expanded_bytes=self.diagnostics_max_expanded_bytes,
            diagnostics_retention_seconds=self.diagnostics_retention_seconds,
            asr_providers=tuple(item.resolved(base) for item in self.asr_providers),
            tts_providers=tuple(item.resolved(base) for item in self.tts_providers),
            asr_chain=self.asr_chain,
            tts_chain=self.tts_chain,
            asr_deadline_seconds=self.asr_deadline_seconds,
            tts_deadline_seconds=self.tts_deadline_seconds,
            asr_overrides=self.asr_overrides,
            tts_overrides=self.tts_overrides,
            asr_fallback_order=self.asr_fallback_order,
        )
