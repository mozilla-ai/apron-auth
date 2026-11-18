"""Identity requests whose failures never chain the token-bearing request."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from apron_auth._discovery import NoTransportError, chosen_transport
from apron_auth._http_errors import http_failure
from apron_auth._json_body import decode_json_body
from apron_auth._limits import httpx_timeout, within_request_limit
from apron_auth.errors import FailureKind, IdentityFetchError

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from apron_auth.models import RequestLimits
    from apron_auth.protocols import TransportFactory


def identity_client(limits: RequestLimits, *, transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    """Build the HTTP client an identity request runs through.

    Args:
        limits: The limits in force for the request.
        transport: Optional transport controlling the outbound connection.

    Returns:
        A client whose every step is bounded by the policy, and which follows no redirect, so the
        token goes to the request's own host and nowhere else.
    """
    return httpx.AsyncClient(transport=transport, timeout=httpx_timeout(limits), follow_redirects=False)


def identity_transport(
    transport_factory: TransportFactory | None, url: str, label: str
) -> httpx.AsyncBaseTransport | None:
    """Return the transport a caller's factory chose for ``url``, or ``None`` where there is no factory.

    A factory is the caller's own code, so it may refuse the connection by policy, fail outright, or
    state no transport at all. None of the three is the provider's fault or an outage, and a later
    attempt reads the same code, so none of them is retried.

    NOTE: The factory is called with a URL alone and before any request is built, so its own error
    carries no credential and is chained.

    Args:
        transport_factory: The caller's factory, or ``None`` where the caller gave none.
        url: A URL on the host the client will reach, which selects the transport. A client serves
            one host, so a handler sending several requests states any one of them, and one whose
            URL carries a credential states the part that names the host.
        label: What the request fetches, such as ``"GitHub identity"``, for the error message.

    Returns:
        The transport for ``url``'s host, or ``None`` where there is no factory.

    Raises:
        IdentityFetchError: If the factory refuses the connection, fails, or returns no transport.
            A factory that returns nothing is refused rather than defaulted, because falling back to
            an unshaped connection would drop the policy the factory states.
    """
    try:
        return chosen_transport(transport_factory, url)
    except NoTransportError:
        msg = f"Failed to fetch {label}: transport_factory returned no transport"
        raise IdentityFetchError(msg, kind=FailureKind.UNEXPECTED) from None
    except Exception as exc:
        msg = f"Failed to fetch {label}: outbound connection refused"
        raise IdentityFetchError(msg, kind=FailureKind.UNEXPECTED) from exc


async def fetch_identity_json(request: Awaitable[httpx.Response], label: str, limits: RequestLimits) -> Any:
    """Await an identity request and return its decoded JSON body.

    NOTE: The request must be sent with ``stream=True``, so the limit on the body it answers with applies.

    Args:
        request: The pending request, which carries the access token.
        label: What the request fetches, such as ``"Google identity"``, for the error message.
        limits: The limits in force, which bound the request as a whole.

    Returns:
        The decoded JSON body.

    Raises:
        IdentityFetchError: If the URL is invalid, the request cannot be sent or fails,
            the endpoint answers with an error status, or the body is not JSON or passes the limit on one.
            The caught error is not attached as its cause or context.
    """
    try:
        answer = await within_request_limit(request, limits)
        answer.response.raise_for_status()
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
            return decode_json_body(answer.body)
        except ValueError:
            failure_message, kind = f"Failed to parse {label} response", FailureKind.REFUSED
    # NOTE: The caught error holds the token-bearing request or the response, so this error must not chain it.
    # This raise stays outside the except blocks, where Python would set __context__ to the caught error.
    raise IdentityFetchError(failure_message, kind=kind)
