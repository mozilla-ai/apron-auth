"""Domain-level descriptions of failed provider HTTP requests."""

from __future__ import annotations

import httpx


def describe_http_error(exc: httpx.HTTPError) -> str:
    """Describe a failed request by its status code or the kind of transport failure.

    The description never includes the request URL, the HTTP client's message text, or its error class names.

    Args:
        exc: The error raised by the request or by its status check.

    Returns:
        ``"HTTP <status>"`` for an error status, or a short phrase naming the kind of transport failure.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return "request timed out"
    if isinstance(exc, httpx.NetworkError):
        return "network error"
    return "request failed"
