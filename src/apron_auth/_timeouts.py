"""The limits a timeout policy puts on one outbound request."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, TypeVar

import httpx

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from apron_auth.models import TimeoutPolicy

_T = TypeVar("_T")

# What a refusal of a request that outlived its limit states. It names no URL and no endpoint.
_WHOLE_REQUEST_REFUSAL = "request did not finish within the time allowed"


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


async def within_request_limit(request: Awaitable[_T], policy: TimeoutPolicy) -> _T:
    """Await one request, refusing it once the policy's whole-request limit passes.

    NOTE: The refusal is raised as the HTTP client's own timeout, so every caller that already classifies
    a failed request reports it as a timeout rather than as an error of a kind it does not recognize.

    Args:
        request: The pending request, which is canceled when the limit passes.
        policy: The limits in force.

    Returns:
        What the request answered with.

    Raises:
        httpx.TimeoutException: If the request does not finish within ``policy.request_seconds``.
            Whatever else the request raises is left alone.
    """
    try:
        async with asyncio.timeout(policy.request_seconds):
            return await request
    except TimeoutError as exc:
        raise httpx.TimeoutException(_WHOLE_REQUEST_REFUSAL) from exc
