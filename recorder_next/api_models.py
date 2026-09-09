"""Small strict DTO primitives shared by HTTP handlers and contract tests.

This module intentionally does not own persistence or route dispatch.  It gives
network boundaries one predictable closed-object check instead of duplicating
ad-hoc ``set(payload)`` expressions across handlers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .errors import ValidationError


@dataclass(frozen=True)
class Field:
    name: str
    required: bool = False
    types: tuple[type, ...] = (object,)
    nullable: bool = False

    def validate(self, value: Any) -> Any:
        if value is None and self.nullable:
            return value
        if self.types != (object,) and not isinstance(value, self.types):
            raise ValidationError(f"{self.name} has an invalid type")
        return value


@dataclass(frozen=True)
class ObjectModel:
    name: str
    fields: tuple[Field, ...]
    additional_properties: bool = False

    @property
    def field_map(self) -> dict[str, Field]:
        return {field.name: field for field in self.fields}

    def validate(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ValidationError(f"{self.name} must be an object")
        field_map = self.field_map
        if not self.additional_properties:
            unknown = set(value).difference(field_map)
            if unknown:
                raise ValidationError(f"{self.name} contains unsupported fields")
        for field in self.fields:
            if field.required and field.name not in value:
                raise ValidationError(f"{self.name} requires {field.name}")
            if field.name in value:
                field.validate(value[field.name])
        return dict(value)


WORKER_CLAIM = ObjectModel(
    "worker claim",
    (Field("owner", types=(str,)), Field("lease_seconds", types=(int,))),
)
WORKER_RECOVER = ObjectModel("worker recover", ())
WORKER_COMPLETE = ObjectModel(
    "worker completion",
    (
        Field("job_id", required=True, types=(str,)),
        Field("owner", required=True, types=(str,)),
        Field("lease_token", required=True, types=(str,)),
        Field("receipt", required=True, types=(Mapping,)),
    ),
)
WORKER_FAIL = ObjectModel(
    "worker failure",
    (
        Field("job_id", required=True, types=(str,)),
        Field("owner", required=True, types=(str,)),
        Field("lease_token", required=True, types=(str,)),
        Field("error_kind", types=(str,)),
        Field("retryable", types=(bool,)),
        Field("status_code", types=(int,), nullable=True),
        Field("retry_after_seconds", types=(int,), nullable=True),
    ),
)
WORKER_RUN = ObjectModel(
    "worker run",
    (Field("owner", types=(str,)), Field("lease_seconds", types=(int,))),
)


__all__ = [
    "Field",
    "ObjectModel",
    "WORKER_CLAIM",
    "WORKER_RECOVER",
    "WORKER_COMPLETE",
    "WORKER_FAIL",
    "WORKER_RUN",
]
