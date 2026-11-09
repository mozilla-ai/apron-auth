"""Identity requests whose failures never chain the token-bearing request."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import TYPE_CHECKING, Any

import httpx

from apron_auth._http_errors import http_failure
from apron_auth._json_body import decode_json_body
from apron_auth._timeouts import httpx_timeout, within_request_limit
from apron_auth.errors import FailureKind, IdentityFetchError

if TYPE_CHECKING:
    from apron_auth.models import TimeoutPolicy
    from apron_auth.protocols import TransportFactory


def identity_client(timeouts: TimeoutPolicy, *, transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    """Build the HTTP client an identity request runs through.

    Args:
        timeouts: The limits in force for the request.
        transport: Optional transport controlling the outbound connection.

    Returns:
        A client whose every step is bounded by the policy, and which follows no redirect, so the
        token goes to the request's own host and nowhere else.
    """
    return httpx.AsyncClient(transport=transport, timeout=httpx_timeout(timeouts), follow_redirects=False)


def identity_transport(
    transport_factory: TransportFactory | None, url: str, label: str
) -> httpx.AsyncBaseTransport | None:
    """Return the transport a caller's factory chose for ``url``, or ``None`` where it gave none.

    A factory is the caller's own code, so it may refuse the connection by policy or fail outright.
    Either way the fault is neither the provider's nor an outage, so the refusal is never retried.

    NOTE: The factory is called with a URL alone and before any request is built, so its own error
    carries no credential and is chained.

    Args:
        transport_factory: The caller's factory, or ``None`` where the caller gave none.
        url: The URL the client will reach, which selects the transport.
        label: What the request fetches, such as ``"GitHub identity"``, for the error message.

    Returns:
        The transport for ``url``, or ``None`` where there is no factory.

    Raises:
        IdentityFetchError: If the factory refuses the connection or fails.
    """
    if transport_factory is None:
        return None
    try:
        return transport_factory(url)
    except Exception as exc:
        msg = f"Failed to fetch {label}: outbound connection refused"
        raise IdentityFetchError(msg, kind=FailureKind.UNEXPECTED) from exc


async def fetch_identity_json(request: Awaitable[httpx.Response], label: str, timeouts: TimeoutPolicy) -> Any:
    """Await an identity request and return its decoded JSON body.

    Args:
        request: The pending request, which carries the access token.
        label: What the request fetches, such as ``"Google identity"``, for the error message.
        timeouts: The limits in force, which bound the request as a whole.

    Returns:
        The decoded JSON body.

    Raises:
        IdentityFetchError: If the URL is invalid, the request cannot be sent or fails,
            the endpoint answers with an error status, or the body is not JSON.
            The caught error is not attached as its cause or context.
    """
    try:
        response = await within_request_limit(request, timeouts)
        response.raise_for_status()
    # NOTE: httpx.InvalidURL is not an httpx.HTTPError, so it needs its own clause.
    except httpx.InvalidURL:
        failure_message, kind = f"Failed to fetch {label}: invalid URL", FailureKind.REFUSED
    except httpx.HTTPError as exc:
        failure = http_failure(exc)
        failure_message, kind = f"Failed to fetch {label}: {failure.description}", failure.kind
    except Exception:
        # A token that is not ASCII cannot go in a header, and the encoding error repeats it.
        failure_message, kind = f"Failed to fetch {label}: request failed", FailureKind.UNEXPECTED
    else:
        try:
            return decode_json_body(response)
        except ValueError:
            failure_message, kind = f"Failed to parse {label} response", FailureKind.REFUSED
    # NOTE: The caught error holds the token-bearing request or the response, so this error must not chain it.
    # This raise stays outside the except blocks, where Python would set __context__ to the caught error.
    raise IdentityFetchError(failure_message, kind=kind)
