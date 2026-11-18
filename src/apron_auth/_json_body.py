"""Decoding of HTTP response bodies as JSON."""

from __future__ import annotations

import json
from typing import Any


def decode_json_body(body: bytes | None) -> Any:
    """Return a response body decoded as JSON.

    The error for an unreadable body carries a fixed message and no chain to the decoder's own error.

    Args:
        body: The body as it arrived, or ``None`` where it passed the limit on one.

    Returns:
        The decoded body.

    Raises:
        ValueError: If the body passed the limit on one, is not JSON, or nests too deeply to decode.
    """
    if body is None:
        msg = "the body is too large to read"
        raise ValueError(msg)
    try:
        return json.loads(body)
    except RecursionError:
        msg = "the body nests too deeply to decode"
    except ValueError:
        msg = "the body is not JSON"
    # NOTE: This raise stays outside the except block, so the error keeps neither the decoder's error nor its frames.
    raise ValueError(msg)
