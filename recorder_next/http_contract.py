"""Exact, side-effect-free HTTP route catalog for Recorder Next.

The service keeps the implementation handlers for compatibility, but route
admission happens through this catalog first.  This prevents prefix-based
handlers from accidentally accepting an undocumented suffix or action.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Mapping

from .errors import NotFoundError
from .openapi import OPENAPI


@dataclass(frozen=True)
class Operation:
    path_template: str
    method: str
    operation_id: str
    deprecated: bool = False
    handler_key: str = ""
    public: bool = False
    principal_policy: str = "principal"
    path_parameters: tuple[str, ...] = ()
    query_parameters: tuple[str, ...] = ()
    header_parameters: tuple[str, ...] = ()
    body_descriptor: tuple[tuple[str, str], ...] = ()
    success_statuses: tuple[str, ...] = ()
    error_statuses: tuple[str, ...] = ()

    @property
    def requires_principal(self) -> bool:
        return self.principal_policy == "principal"

    @property
    def path_params(self) -> tuple[str, ...]:
        return self.path_parameters

    @property
    def query_params(self) -> tuple[str, ...]:
        return self.query_parameters

    @property
    def headers(self) -> tuple[str, ...]:
        return self.header_parameters

    @property
    def body(self) -> tuple[tuple[str, str], ...]:
        return self.body_descriptor


def _template_regex(template: str) -> re.Pattern[str]:
    parts = []
    for part in template.strip("/").split("/") if template != "/" else []:
        if part.startswith("{") and part.endswith("}"):
            parts.append(r"[^/]+")
        else:
            parts.append(re.escape(part))
    return re.compile(r"^/" + "/".join(parts) + r"/?$")


def _resolve_parameter(parameter: Any) -> Mapping[str, Any]:
    if isinstance(parameter, Mapping) and "$ref" in parameter:
        ref = parameter.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/parameters/"):
            value = OPENAPI.get("components", {}).get("parameters", {}).get(ref.rsplit("/", 1)[-1])
            if isinstance(value, Mapping):
                return value
    return parameter if isinstance(parameter, Mapping) else {}


def _operation_descriptor(path: str, method: str, operation: Mapping[str, Any]) -> Operation:
    parameters: list[Mapping[str, Any]] = []
    path_item = OPENAPI.get("paths", {}).get(path, {})
    if isinstance(path_item, Mapping):
        parameters.extend(_resolve_parameter(item) for item in path_item.get("parameters", []))
    parameters.extend(_resolve_parameter(item) for item in operation.get("parameters", []))
    by_location = {
        "path": tuple(sorted({str(item["name"]) for item in parameters if item.get("in") == "path" and isinstance(item.get("name"), str)})),
        "query": tuple(sorted({str(item["name"]) for item in parameters if item.get("in") == "query" and isinstance(item.get("name"), str)})),
        "header": tuple(sorted({str(item["name"]) for item in parameters if item.get("in") == "header" and isinstance(item.get("name"), str)})),
    }
    body_descriptor: list[tuple[str, str]] = []
    request_body = operation.get("requestBody")
    if isinstance(request_body, Mapping):
        content = request_body.get("content", {})
        if isinstance(content, Mapping):
            for media_type, media_schema in content.items():
                schema = media_schema.get("schema", {}) if isinstance(media_schema, Mapping) else {}
                ref = schema.get("$ref") if isinstance(schema, Mapping) else None
                body_descriptor.append((str(media_type), str(ref or schema.get("type", "object"))))
    statuses = operation.get("responses", {})
    success = tuple(sorted(str(status) for status in statuses if str(status).startswith("2") or str(status) == "304")) if isinstance(statuses, Mapping) else ()
    errors = tuple(sorted(str(status) for status in statuses if str(status).startswith(("4", "5")))) if isinstance(statuses, Mapping) else ()
    operation_id = str(operation.get("operationId", f"{method.lower()}_{path}"))
    public = path in {"/v1/health", "/v1/openapi.json", "/healthz"}
    updates_public = path.startswith("/v1/updates/")
    policy = "public" if public else "none" if updates_public else "principal"
    return Operation(
        path,
        method.upper(),
        operation_id,
        deprecated=bool(operation.get("deprecated", False)),
        handler_key=str(operation.get("x-handler-key", operation_id)),
        public=public,
        principal_policy=policy,
        path_parameters=by_location["path"],
        query_parameters=by_location["query"],
        header_parameters=by_location["header"],
        body_descriptor=tuple(body_descriptor),
        success_statuses=success,
        error_statuses=errors,
    )


def _iter_operations() -> Iterable[Operation]:
    # The generic eavesdrop action was retained in older documents but is not
    # a public route.  Only the named lifecycle actions are admitted below.
    excluded = {
        "/v1/eavesdrop/{session_id}/{action}",
        "/v1/internal/worker/{action}",
    }
    for path, item in OPENAPI.get("paths", {}).items():
        if path in excluded or not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method in {"get", "post", "put", "patch", "delete", "head"} and isinstance(operation, dict):
                yield Operation(
                    **_operation_descriptor(path, method, operation).__dict__,
                )


# Additive runtime aliases are explicit and therefore cannot be opened by a
# broad prefix check.  They are also represented in the generated OpenAPI.
_ALIAS_OPERATIONS = tuple(
    _operation_descriptor(path, method, OPENAPI["paths"][path][method])
    for path, method in (
        ("/healthz", "get"),
        ("/v1/devices/register", "post"),
        ("/v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}", "post"),
        ("/v1/turns/{turn_id}/events/{event_id}", "post"),
        ("/v1/updates/{channel}/manifest.json", "get"),
    )
)


_operation_map: dict[tuple[str, str], Operation] = {}
for _operation in tuple(_iter_operations()) + _ALIAS_OPERATIONS:
    _operation_map.setdefault((_operation.path_template, _operation.method), _operation)
_OPERATIONS = tuple(_operation_map.values())
_COMPILED = tuple((operation, _template_regex(operation.path_template)) for operation in _OPERATIONS)


def match_operation(path: str, method: str) -> Operation:
    """Return the exact catalog operation or raise a non-mutating 404."""

    normalized_method = "GET" if method.upper() == "HEAD" else method.upper()
    for operation, pattern in _COMPILED:
        if operation.method == normalized_method and pattern.fullmatch(path):
            return operation
    raise NotFoundError("route not found")


def route_catalog() -> tuple[Operation, ...]:
    """Return an immutable snapshot for tests and OpenAPI parity checks."""

    return tuple(_OPERATIONS)
