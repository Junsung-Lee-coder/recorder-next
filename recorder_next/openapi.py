"""OpenAPI projection for the authoritative Recorder HTTP catalog."""

from .http_contract import (
    OPENAPI,
    build_openapi_document,
    validate_openapi_contract,
)

__all__ = ["OPENAPI", "build_openapi_document", "validate_openapi_contract"]