"""The shared JSON body decoder reports every unreadable body as a ``ValueError``, and every decode site uses it."""

from __future__ import annotations

import ast
import gzip
from pathlib import Path

import httpx
import pytest
from support import LazyBodyTransport, LazyByteStream

import apron_auth
from apron_auth._json_body import decode_json_body
from apron_auth._timeouts import within_request_limit
from apron_auth.models import TimeoutPolicy

_PACKAGE_ROOT = Path(apron_auth.__file__).parent

# A body small enough that one chunk of it cannot reach a cap stated in this test.
_CHUNK_BYTES = 1024


async def _streamed(body: bytes, policy: TimeoutPolicy, *, headers: dict[str, str] | None = None) -> object:
    """Decode ``body`` as it arrives from a transport that yields it one chunk at a time."""
    stream = LazyByteStream([body[at : at + _CHUNK_BYTES] for at in range(0, len(body), _CHUNK_BYTES)])
    async with httpx.AsyncClient(transport=LazyBodyTransport(stream, headers=headers)) as client:
        request = client.build_request("GET", "https://documents.test/d")
        return decode_json_body(await within_request_limit(client.send(request, stream=True), policy))


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


async def test_returns_the_decoded_body() -> None:
    assert await _streamed(b'{"ok": true}', TimeoutPolicy()) == {"ok": True}


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
async def test_an_unreadable_body_is_a_value_error_with_no_chain(content: bytes, message: str) -> None:
    """Every unreadable body gives one fixed message, with no chain to the decoder's error, which holds the body."""
    with pytest.raises(ValueError) as excinfo:
        await _streamed(content, TimeoutPolicy(max_body_bytes=1_000_000))

    assert str(excinfo.value) == message
    assert excinfo.value.__context__ is None
    assert excinfo.value.__cause__ is None
    assert "SECRET-ISH-DATA" not in repr(excinfo.value.args)


class TestTheBodyIsReadUnderTheLimit:
    """The limit is counted as the body decodes, so a body past it is refused rather than held."""

    async def test_a_body_at_the_limit_is_read(self) -> None:
        body = b'{"filler": "' + b"f" * 900 + b'"}'

        assert await _streamed(body, TimeoutPolicy(max_body_bytes=len(body))) == {"filler": "f" * 900}

    async def test_a_body_that_states_nothing_is_read_as_the_empty_body_it_is(self) -> None:
        """A response that states no body states one the limit allowed, which a refused body does not."""
        stream = LazyByteStream([])

        async with httpx.AsyncClient(transport=LazyBodyTransport(stream)) as client:
            request = client.build_request("GET", "https://documents.test/d")
            answer = await within_request_limit(client.send(request, stream=True), TimeoutPolicy())

        assert answer.body == b""
        with pytest.raises(ValueError, match="the body is not JSON"):
            decode_json_body(answer)

    async def test_a_body_past_the_limit_is_refused_as_unreadable(self) -> None:
        body = b'{"filler": "' + b"f" * 100_000 + b'"}'

        with pytest.raises(ValueError, match="the body is too large to read") as excinfo:
            await _streamed(body, TimeoutPolicy(max_body_bytes=4096))

        assert excinfo.value.__context__ is None
        assert excinfo.value.__cause__ is None

    async def test_a_body_past_the_limit_is_refused_before_the_rest_of_it_arrives(self) -> None:
        """A cap on a body already read bounds nothing, because the allocation has happened."""
        body = b'{"filler": "' + b"f" * 1_000_000 + b'"}'
        chunks = [body[at : at + _CHUNK_BYTES] for at in range(0, len(body), _CHUNK_BYTES)]
        stream = LazyByteStream(chunks)

        async with httpx.AsyncClient(transport=LazyBodyTransport(stream)) as client:
            request = client.build_request("GET", "https://documents.test/d")
            answer = await within_request_limit(client.send(request, stream=True), TimeoutPolicy(max_body_bytes=4096))

        assert stream.pulled < len(body) / 10
        assert answer.body is None, "a body past the limit states no body, which an empty one does not"
        with pytest.raises(ValueError, match="the body is too large to read"):
            decode_json_body(answer)

    async def test_a_compressed_body_that_expands_past_the_limit_is_refused(self) -> None:
        """A limit on what crosses the wire is not a limit on what the decoder produces."""
        compressed = gzip.compress(b'{"filler": "' + b"f" * 5_000_000 + b'"}')
        headers = {"content-type": "application/json", "content-encoding": "gzip"}

        with pytest.raises(ValueError, match="the body is too large to read"):
            await _streamed(compressed, TimeoutPolicy(max_body_bytes=1_048_576), headers=headers)

        assert len(compressed) < 1_048_576
