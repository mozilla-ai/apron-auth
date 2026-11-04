"""Domain-level classification of failed provider HTTP requests."""

from __future__ import annotations

from typing import NamedTuple

import httpx

from apron_auth.errors import FailureKind

# The lowest status code of each band this module tells apart.
_FIRST_CLIENT_ERROR_STATUS = 400
_FIRST_REDIRECT_STATUS = 300
_FIRST_SERVER_ERROR_STATUS = 500
# The client error status that reports a rate limit (RFC 6585).
_RATE_LIMITED_STATUS = 429
# The header a response states to say its condition is temporary and when to come back (RFC 9110 section 10.2.3).
_RETRY_AFTER_HEADER = "retry-after"


class HttpFailure(NamedTuple):
    """How a failed request is reported: the kind a caller acts on, and a short description for the message."""

    kind: FailureKind
    description: str


def http_failure(exc: httpx.HTTPError) -> HttpFailure:
    """Classify a failed request by its status code or the kind of transport failure.

    The description never includes the request URL, the HTTP client's message text, or its error class names.

    Args:
        exc: The error raised by the request or by its status check.

    Returns:
        The failure kind, and ``"HTTP <status>"`` for an error status or a short phrase naming the transport failure.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return response_failure(exc.response)
    if isinstance(exc, httpx.TimeoutException):
        return HttpFailure(FailureKind.TIMEOUT, "request timed out")
    if isinstance(exc, httpx.NetworkError):
        return HttpFailure(FailureKind.UNREACHABLE, "network error")
    return HttpFailure(FailureKind.UNREACHABLE, "request failed")


def response_failure(response: httpx.Response) -> HttpFailure:
    """Classify a failed response by what it states about itself, and then by its status.

    A status alone cannot tell a throttle from a refusal where a server answers both with one status, so a
    response stating when to come back is read as temporary whatever its status is. A redirect is excepted,
    because this library follows none and no wait makes an endpoint stop redirecting.

    Args:
        response: The response to classify, which its caller has already read as a failure.

    Returns:
        The failure kind and ``"HTTP <status>"``.
    """
    status = response.status_code
    failure = status_failure(status)
    if _FIRST_REDIRECT_STATUS <= status < _FIRST_CLIENT_ERROR_STATUS:
        return failure
    if response.headers.get(_RETRY_AFTER_HEADER, "").strip():
        return HttpFailure(FailureKind.SERVER_ERROR, failure.description)
    return failure


def status_failure(status: int) -> HttpFailure:
    """Classify a response by its status code.

    A server error or a rate limit may pass on retry.
    A redirect is a refusal, because this library follows none.
    Any other status is the other side rejecting the request as sent.

    Args:
        status: The HTTP status code of the response.

    Returns:
        The failure kind and ``"HTTP <status>"``.
    """
    description = f"HTTP {status}"
    if status >= _FIRST_SERVER_ERROR_STATUS or status == _RATE_LIMITED_STATUS:
        return HttpFailure(FailureKind.SERVER_ERROR, description)
    if _FIRST_REDIRECT_STATUS <= status < _FIRST_CLIENT_ERROR_STATUS:
        return HttpFailure(FailureKind.REFUSED, description)
    return HttpFailure(FailureKind.REJECTED, description)
