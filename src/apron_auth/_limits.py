"""The limits this library puts on one outbound request."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from collections.abc import Awaitable, Mapping

    from apron_auth.models import RequestLimits

# What a refusal of a request that outlived its limit states. It names no URL and no endpoint.
_WHOLE_REQUEST_REFUSAL = "request did not finish within the time allowed"


@dataclass(frozen=True)
class BoundedResponse:
    """One response and the body it stated, read under the limits in force.

    A body past the limit is stated as no body at all rather than as the bytes read before it passed,
    so a reader that takes the body for what arrived cannot mistake a refused body for an empty one.

    NOTE: The body is held here rather than on the response, which never reads its own content, so
    ``response.content`` and ``response.text`` state nothing about what arrived.
    NOTE: The body states nothing in a repr, and this is no sequence, because the other side writes
    the body and may echo a credential in it. An error reporter records the frame locals of every
    frame on a traceback, and a caller that holds this is on the traceback of the error it raises.

    Attributes:
        response: The response, for its status and its headers.
        body: The body as it decoded, or ``None`` where the body passed the limit on one.
    """

    response: httpx.Response
    body: bytes | None = field(repr=False)


def httpx_timeout(limits: RequestLimits) -> httpx.Timeout:
    """Return the per-step limits an HTTP client applies to one request.

    Each step of a request gets the whole-request limit, which bounds no request on its own because a
    request takes as many steps as the other side answers in. ``within_request_limit`` bounds the request.

    Args:
        limits: The limits in force.

    Returns:
        The limits on connecting, reading, writing, and waiting for a pooled connection.
    """
    return httpx.Timeout(limits.request_seconds, connect=limits.connect_seconds)


async def streamed(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    auth: tuple[str, str] | None = None,
    data: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    json: Any = None,
    params: Mapping[str, Any] | None = None,
) -> httpx.Response:
    """Send one request and answer before its body arrives, so a limit can be put on the body.

    Nothing is built until this is awaited, so a header or a URL that cannot be sent fails where the
    caller awaits the request rather than where it describes one. A caller that classifies a failed
    request therefore reaches that failure too.

    NOTE: This states the request as its parts rather than taking a built one, for the same reason.
    A built request is a local of the caller, so it is on the traceback of the error the caller raises
    and its repr states a URL that may carry a credential. A local here is not, because a failed
    request is reported as a new error raised outside the except block.

    Args:
        client: The client that sends the request.
        method: The HTTP method.
        url: The URL to request.
        auth: The credential to present, which is presented on this request alone. It states what the
            request presents outright, so a client carrying a credential of its own presents none here.
        data: The form fields to send.
        headers: The headers to send.
        json: The value to send as a JSON body.
        params: The query parameters to send.

    Returns:
        The response, whose body has not been read.
    """
    request = client.build_request(method, url, data=data, headers=headers, json=json, params=params)
    return await client.send(request, auth=auth, stream=True)


async def within_request_limit(request: Awaitable[httpx.Response], limits: RequestLimits) -> BoundedResponse:
    """Await one streamed request and read its body, refusing it past the limits in force.

    The body is counted as it decodes and the read stops at the byte that passes the limit, so no more
    than the limit is retained however far a compressed body would expand. A body that passed the limit
    is reported rather than raised, because what an unreadable body means belongs to whoever reads it.
    One limit covers receiving the response and reading its body, which arrives after it.

    NOTE: The limit bounds what is retained, not what one decode step allocates. The HTTP client
    decompresses a whole chunk off the socket before this sees it, so a compressed body can allocate
    several times the limit for the step it is refused on.
    NOTE: The refusal is raised as the HTTP client's own timeout, so every caller that already classifies
    a failed request reports it as a timeout rather than as an error of a kind it does not recognize.
    NOTE: The request must be one ``streamed`` built. A request sent any other way reads its whole body
    before this is reached, and no limit can then apply to it.

    Args:
        request: The pending streamed request, which is canceled when the limit passes.
        limits: The limits in force.

    Returns:
        The response and the body it stated.

    Raises:
        httpx.TimeoutException: If the request and its body do not arrive within ``limits.request_seconds``.
            Whatever else the request raises is left alone.
    """
    try:
        async with asyncio.timeout(limits.request_seconds):
            response = await request
            try:
                return await _body_within_limit(response, limits.max_body_bytes)
            finally:
                await response.aclose()
    except TimeoutError as exc:
        raise httpx.TimeoutException(_WHOLE_REQUEST_REFUSAL) from exc


async def _body_within_limit(response: httpx.Response, max_bytes: int) -> BoundedResponse:
    """Read the body of a streamed response, stopping at the byte that passes ``max_bytes``.

    Args:
        response: The streamed response, whose body has not been read.
        max_bytes: The most decoded bytes to hold.

    The bytes read are held in one buffer, so what this holds follows the limit rather than the number
    of chunks the other side split the body into.

    Returns:
        The response and the body it stated, which is ``None`` where the body passed the limit.
    """
    read = bytearray()
    # NOTE: The caller closes the response, which releases the stream this abandons past the limit.
    async for chunk in response.aiter_bytes():
        if len(read) + len(chunk) > max_bytes:
            return BoundedResponse(response, None)
        read += chunk
    return BoundedResponse(response, bytes(read))
