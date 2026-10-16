"""The shared JSON body decoder reports every unreadable body as a ``ValueError``, and every decode site uses it."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest

import apron_auth
from apron_auth._json_body import decode_json_body

_PACKAGE_ROOT = Path(apron_auth.__file__).parent


def _decodes_a_body_directly(call: ast.Call) -> bool:
    """Return whether a call decodes a response body without the shared decoder."""
    if not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr == "json":
        return not call.args and not call.keywords
    if call.func.attr == "loads" and len(call.args) == 1:
        argument = call.args[0]
        return isinstance(argument, ast.Attribute) and argument.attr in {"content", "text"}
    return False


def _direct_body_decodes(source: str) -> list[int]:
    """Return the line of each call that decodes a response body directly."""
    tree = ast.parse(source)
    return sorted(
        node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call) and _decodes_a_body_directly(node)
    )


@pytest.mark.parametrize(
    "decode",
    [
        "response.json()",
        "exc.response.json()",
        "json.loads(response.content)",
        "json.loads(response.text)",
    ],
)
def test_the_scan_finds_a_direct_decode(decode: str) -> None:
    assert _direct_body_decodes(f"data = {decode}\n") == [1]


@pytest.mark.parametrize(
    "allowed",
    [
        "json.loads(compact.payload)",
        "await client.post(url, json=payload)",
        "decode_json_body(response)",
    ],
)
def test_the_scan_allows_other_decodes_and_keyword_arguments(allowed: str) -> None:
    assert _direct_body_decodes(f"data = {allowed}\n") == []


@pytest.mark.parametrize(
    "path",
    sorted(path for path in _PACKAGE_ROOT.rglob("*.py") if path.name != "_json_body.py"),
    ids=lambda path: str(path.relative_to(_PACKAGE_ROOT)),
)
def test_every_decode_site_uses_the_shared_decoder(path: Path) -> None:
    """A direct decode misses the recursion error a deeply nested body raises, so no module may decode on its own.

    NOTE: The scan matches the shape of a call, not the type of its receiver.
    A zero-argument ``.json()`` on an object that is not a response is a false positive, and the fix is
    to narrow ``_decodes_a_body_directly``, not to skip the module.
    The scan does not see a ``.json()`` call with arguments, or a body bound to a name before it is decoded.
    """
    lines = _direct_body_decodes(path.read_text(encoding="utf-8"))
    assert lines == [], f"{path.name} decodes a response body directly at {lines}; use decode_json_body"


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
