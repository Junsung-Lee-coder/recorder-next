from __future__ import annotations

import datetime as dt
from dataclasses import dataclass


def _parse_utc(value: str | dt.datetime) -> dt.datetime:
    if isinstance(value, dt.datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise TypeError("clock value must be an RFC3339 string or datetime")
    if parsed.tzinfo is None:
        raise ValueError("clock value must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


@dataclass
class DeterministicClock:
    """Small injectable UTC clock for timer and restart acceptance fixtures."""

    current: dt.datetime | str

    def __post_init__(self) -> None:
        self.current = _parse_utc(self.current)

    def now_datetime(self) -> dt.datetime:
        return _parse_utc(self.current)

    def now(self) -> str:
        return self.now_datetime().isoformat(timespec="milliseconds")

    def __call__(self) -> str:
        return self.now()

    def set(self, value: str | dt.datetime) -> None:
        self.current = _parse_utc(value)

    def advance(self, *, seconds: int = 0, minutes: int = 0) -> str:
        self.current = self.now_datetime() + dt.timedelta(seconds=seconds, minutes=minutes)
        return self.now()
