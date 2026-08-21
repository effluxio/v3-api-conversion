"""
Exceptions for the Efflux v3 API client.

v3 uses RFC 7807 Problem Details for errors instead of the v2 { "error": "..." } format.
"""
from typing import Optional


class EffluxError(Exception):
    """Base exception for all Efflux errors."""


class EffluxAPIError(EffluxError):
    """
    Raised when the API returns an error response (4xx, 5xx).

    v3 error body shape (RFC 7807):
    {
        "type": "https://api.efflux.io/v3/errors/...",
        "title": "Human-readable title",
        "status": 400,
        "detail": "Specific error description",
        "instance": "/v3/scans",
        "errors": [{"field": "ports", "message": "no valid ports"}],
        "rate_limit": { ... }   # present on 429 only
    }
    """

    def __init__(
        self,
        status_code: int,
        detail: str,
        title: Optional[str] = None,
        error_type: Optional[str] = None,
        instance: Optional[str] = None,
        field_errors: Optional[list] = None,
        rate_limit: Optional[dict] = None,
        raw_body: Optional[dict] = None,
    ):
        self.status_code = status_code
        self.detail = detail
        self.title = title
        self.error_type = error_type
        self.instance = instance
        self.field_errors = field_errors or []
        self.rate_limit = rate_limit
        self.raw_body = raw_body
        super().__init__(f"HTTP {status_code}: {detail}")

    @classmethod
    def from_response(cls, status_code: int, body: dict) -> "EffluxAPIError":
        """Parse an RFC 7807 Problem Details response body."""
        detail = body.get("detail") or body.get("error") or "Unknown error"
        exc = cls(
            status_code=status_code,
            detail=detail,
            title=body.get("title"),
            error_type=body.get("type"),
            instance=body.get("instance"),
            field_errors=body.get("errors", []),
            rate_limit=body.get("rate_limit"),
            raw_body=body,
        )
        if status_code == 400:
            return EffluxValidationError(
                status_code=status_code,
                detail=detail,
                title=exc.title,
                error_type=exc.error_type,
                instance=exc.instance,
                field_errors=exc.field_errors,
                rate_limit=exc.rate_limit,
                raw_body=exc.raw_body,
            )
        if status_code == 401 or status_code == 403:
            return EffluxAuthError(
                status_code=status_code,
                detail=detail,
                title=exc.title,
                error_type=exc.error_type,
                instance=exc.instance,
                field_errors=exc.field_errors,
                rate_limit=exc.rate_limit,
                raw_body=exc.raw_body,
            )
        if status_code == 404:
            return EffluxNotFoundError(
                status_code=status_code,
                detail=detail,
                title=exc.title,
                error_type=exc.error_type,
                instance=exc.instance,
                field_errors=exc.field_errors,
                rate_limit=exc.rate_limit,
                raw_body=exc.raw_body,
            )
        if status_code == 429:
            return EffluxRateLimitError(
                status_code=status_code,
                detail=detail,
                title=exc.title,
                error_type=exc.error_type,
                instance=exc.instance,
                field_errors=exc.field_errors,
                rate_limit=exc.rate_limit,
                raw_body=exc.raw_body,
            )
        return exc


class EffluxValidationError(EffluxAPIError):
    """Raised on HTTP 400 — invalid request body or parameters."""

    @property
    def fields(self) -> dict:
        """Returns a dict of field name → error message."""
        return {e["field"]: e["message"] for e in self.field_errors if "field" in e}


class EffluxAuthError(EffluxAPIError):
    """Raised on HTTP 401 or 403 — invalid API key or insufficient permissions."""


class EffluxNotFoundError(EffluxAPIError):
    """Raised on HTTP 404 — resource not found."""


class EffluxRateLimitError(EffluxAPIError):
    """
    Raised on HTTP 429 — rate limit exceeded.

    Check self.rate_limit for retry timing:
    {
        "limit": 100,
        "remaining": 0,
        "reset_at": "2026-08-20T10:00:00Z",
        "retry_after_seconds": 47
    }
    """

    @property
    def retry_after_seconds(self) -> Optional[int]:
        if self.rate_limit:
            return self.rate_limit.get("retry_after_seconds")
        return None

    @property
    def reset_at(self) -> Optional[str]:
        if self.rate_limit:
            return self.rate_limit.get("reset_at")
        return None
