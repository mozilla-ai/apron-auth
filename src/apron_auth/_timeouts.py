"""The limits a policy puts on one outbound request."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, NamedTuple

import httpx

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from apron_auth.models import TimeoutPolicy

# What a refusal of a request that outlived its limit states. It names no URL and no endpoint.
_WHOLE_REQUEST_REFUSAL = "request did not finish within the time allowed"


class BoundedResponse(NamedTuple):
    """One response and the body it stated, read under the limits in force.

    NOTE: The body is held here rather than on the response, which never reads its own content, so
    ``response.content`` and ``response.text`` state nothing about what arrived.

    Attributes:
        response: The response, for its status and its headers.
        body: The body as it decoded, or empty where the body passed the limit on one.
        complete: Whether the whole body arrived.
    """

    response: httpx.Response
    body: bytes
    complete: bool


def httpx_timeout(policy: TimeoutPolicy) -> httpx.Timeout:
    """Return the per-step limits an HTTP client applies under ``policy``.

    Each step of a request gets the whole-request limit, which bounds no request on its own because a
    request takes as many steps as the other side answers in. ``within_request_limit`` bounds the request.

    Args:
        policy: The limits in force.

    Returns:
        The limits on connecting, reading, writing, and waiting for a pooled connection.
    """
    return httpx.Timeout(policy.request_seconds, connect=policy.connect_seconds)


async def within_request_limit(request: Awaitable[httpx.Response], policy: TimeoutPolicy) -> BoundedResponse:
    """Await one streamed request and read its body, refusing it past the policy's limits.

    The body is counted as it decodes and the read stops at the byte that passes the limit, so a
    compressed body that expands past it is never held whole. A body that passed the limit is reported
    rather than raised, because what an unreadable body means belongs to whoever reads it.
    One limit covers receiving the response and reading its body, which arrives after it.

    NOTE: The refusal is raised as the HTTP client's own timeout, so every caller that already classifies
    a failed request reports it as a timeout rather than as an error of a kind it does not recognize.
    NOTE: The request must be sent with ``stream=True``, which answers before the body arrives. One sent
    without it reads the body unbounded before this is reached.

    Args:
        request: The pending streamed request, which is canceled when the limit passes.
        policy: The limits in force.

    Returns:
        The response and the body it stated.

    Raises:
        httpx.TimeoutException: If the request and its body do not arrive within ``policy.request_seconds``.
            Whatever else the request raises is left alone.
    """
    try:
        async with asyncio.timeout(policy.request_seconds):
            response = await request
            try:
                return await _body_within_limit(response, policy.max_body_bytes)
            finally:
                await response.aclose()
    except TimeoutError as exc:
        raise httpx.TimeoutException(_WHOLE_REQUEST_REFUSAL) from exc


async def _body_within_limit(response: httpx.Response, max_bytes: int) -> BoundedResponse:
    """Read the body of a streamed response, stopping at the byte that passes ``max_bytes``.

    Args:
        response: The streamed response, whose body has not been read.
        max_bytes: The most decoded bytes to hold.

    Returns:
        The response and the body it stated, which is empty where the body passed the limit.
    """
    read: list[bytes] = []
    size = 0
    # NOTE: The caller closes the response, which releases the stream this abandons past the limit.
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > max_bytes:
            return BoundedResponse(response, b"", complete=False)
        read.append(chunk)
    return BoundedResponse(response, b"".join(read), complete=True)
