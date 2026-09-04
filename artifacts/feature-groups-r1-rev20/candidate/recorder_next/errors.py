class RecorderError(Exception):
    """Base error with a stable machine-readable API code."""

    code = "RECORDER_ERROR"
    status = 400

    def __init__(self, message: str = "Recorder request failed", *, code: str | None = None):
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code


class ValidationError(RecorderError):
    code = "VALIDATION_ERROR"
    status = 400


class NotFoundError(RecorderError):
    code = "NOT_FOUND"
    status = 404


class ConflictError(RecorderError):
    code = "CONFLICT"
    status = 409


class RangeNotSatisfiable(RecorderError):
    code = "RANGE_NOT_SATISFIABLE"
    status = 416


class TurnIdConflict(ConflictError):
    code = "TURN_ID_CONFLICT"


class ChunkConflict(ConflictError):
    code = "CHUNK_CONFLICT"


class MissingParts(ConflictError):
    code = "MISSING_PARTS"


class LeaseConflict(ConflictError):
    code = "LEASE_CONFLICT"
    status = 409


class UnauthorizedError(RecorderError):
    code = "UNAUTHORIZED"
    status = 401


class ProviderError(RecorderError):
    code = "PROVIDER_ERROR"
    status = 502


class NotReadyError(RecorderError):
    code = "NOT_READY"
    status = 409


class QuotaExceeded(ConflictError):
    code = "QUOTA_EXCEEDED"
