"""The shared JSON body decoder reports every unreadable body as a ``ValueError``."""

from __future__ import annotations

import httpx
import pytest

from apron_auth._json_body import decode_json_body


def test_returns_the_decoded_body() -> None:
    assert decode_json_body(httpx.Response(200, json={"ok": True})) == {"ok": True}


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"not json", "the body is not JSON"),
        (b'{"secret": "SECRET-ISH-DATA"', "the body is not JSON"),  # pragma: allowlist secret
        (b"\xff\xfe\xfd", "the body is not JSON"),
        (b"[" * 100_000 + b"]" * 100_000, "the body nests too deeply to decode"),
    ],
    ids=["not JSON", "truncated JSON", "not text", "deeply nested"],
)
def test_an_unreadable_body_is_a_value_error_with_no_chain(content: bytes, message: str) -> None:
    """Every unreadable body gives one fixed message, with no chain to the decoder's error, which holds the body."""
    with pytest.raises(ValueError) as excinfo:
        decode_json_body(httpx.Response(200, content=content))

    assert str(excinfo.value) == message
    assert excinfo.value.__context__ is None
    assert excinfo.value.__cause__ is None
    assert "SECRET-ISH-DATA" not in repr(excinfo.value.args)
