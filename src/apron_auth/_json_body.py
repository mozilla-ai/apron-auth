"""Decoding of HTTP response bodies as JSON."""

from __future__ import annotations

from typing import Any

import httpx


def decode_json_body(response: httpx.Response) -> Any:
    """Return the response body decoded as JSON.

    The error for an unreadable body carries a fixed message and no chain to the decoder's own error.

    Args:
        response: The response whose body to decode. The body must already be read.

    Returns:
        The decoded body.

    Raises:
        ValueError: If the body is not JSON, or nests too deeply to decode.
    """
    try:
        return response.json()
    except RecursionError:
        msg = "the body nests too deeply to decode"
    except ValueError:
        msg = "the body is not JSON"
    # NOTE: This raise stays outside the except block, so the error keeps neither the decoder's error nor its frames.
    raise ValueError(msg)
