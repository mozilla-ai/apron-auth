"""Identity requests whose failures never chain the token-bearing request."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import httpx

from apron_auth._http_errors import describe_http_error
from apron_auth._json_body import decode_json_body
from apron_auth.errors import IdentityFetchError


async def fetch_identity_json(request: Awaitable[httpx.Response], label: str) -> Any:
    """Await an identity request and return its decoded JSON body.

    Args:
        request: The pending request, which carries the access token.
        label: What the request fetches, such as ``"Google identity"``, for the error message.

    Returns:
        The decoded JSON body.

    Raises:
        IdentityFetchError: If the URL is invalid, the request cannot be sent or fails,
            the endpoint answers with an error status, or the body is not JSON.
            The caught error is not attached as its cause or context.
    """
    try:
        response = await request
        response.raise_for_status()
    # NOTE: httpx.InvalidURL is not an httpx.HTTPError, so it needs its own clause.
    except httpx.InvalidURL:
        failure_message = f"Failed to fetch {label}: invalid URL"
    except httpx.HTTPError as exc:
        failure_message = f"Failed to fetch {label}: {describe_http_error(exc)}"
    except Exception:
        # A token that is not ASCII cannot go in a header, and the encoding error repeats it.
        failure_message = f"Failed to fetch {label}: request failed"
    else:
        try:
            return decode_json_body(response)
        except ValueError:
            failure_message = f"Failed to parse {label} response"
    # NOTE: The caught error holds the token-bearing request or the response, so this error must not chain it.
    # This raise stays outside the except blocks, where Python would set __context__ to the caught error.
    raise IdentityFetchError(failure_message)
