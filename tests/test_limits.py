from __future__ import annotations

import ast
import asyncio
import tracemalloc
from pathlib import Path

import httpx
import pytest
from support import LazyBodyTransport, LazyByteStream

from apron_auth._http_errors import http_failure
from apron_auth._limits import BoundedResponse, httpx_timeout, within_request_limit
from apron_auth.errors import FailureKind
from apron_auth.models import RequestLimits
from apron_auth.providers import google

# How far past the limit a read may hold while it runs, which a chunk of its own size costs nothing to meet.
_CHUNK_OVERHEAD_ALLOWED = 10

# The HTTP clients this library builds, each of which states the per-step limits in force.
_CLIENTS = {"AsyncClient", "AsyncOAuth2Client"}

# The functions that await a request under the limits in force, and so state what may be given to them.
_BOUNDED_AWAITS = {"fetch_identity_json", "within_request_limit"}

# The one function that sends a request, which leaves the body unread so a limit can be put on it.
_SENDER_OF_RECORD = "streamed"

# The client methods that send a request.
_SENDERS = {"fetch_token", "get", "post", "request", "send"}

# The functions that build a provider configuration, each of which a caller states its limits through.
_CONFIG_BUILDERS = {"preset", "sign_in_preset", "to_provider_config"}

# The library's source tree, walked to keep every request path bounded.
_SRC = Path(__file__).resolve().parents[1] / "src" / "apron_auth"


def _sends_of_the_librarys_own(path: Path) -> list[ast.AST]:
    """Return every node of ``path`` outside the one function that is allowed to send a request."""
    tree = ast.parse(path.read_text())
    of_record = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == _SENDER_OF_RECORD and not node.col_offset
    ]
    excused = {id(node) for definition in of_record for node in ast.walk(definition)}
    return [node for node in ast.walk(tree) if id(node) not in excused]


class TestHttpxTimeout:
    def test_every_step_of_a_request_is_bounded(self) -> None:
        limits = httpx_timeout(RequestLimits(connect_seconds=2.0, request_seconds=7.0))

        assert limits.connect == 2.0
        assert limits.read == 7.0
        assert limits.write == 7.0
        assert limits.pool == 7.0


class _RefusingTransport(httpx.AsyncBaseTransport):
    """A transport that refuses every request with the error it was built for."""

    def __init__(self, refusal: Exception) -> None:
        self._refusal = refusal

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise self._refusal


class _SleepingTransport(httpx.AsyncBaseTransport):
    """A transport that answers no request before the limit can pass."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(60)
        raise AssertionError


class TestWithinRequestLimit:
    @staticmethod
    def _client(transport: httpx.AsyncBaseTransport) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport)

    @staticmethod
    async def _answer(client: httpx.AsyncClient, limits: RequestLimits) -> BoundedResponse:
        request = client.build_request("GET", "https://documents.test/d")
        return await within_request_limit(client.send(request, stream=True), limits)

    async def test_a_request_that_finishes_in_time_answers_normally(self) -> None:
        stream = LazyByteStream([b'{"ok": true}'])

        async with self._client(LazyBodyTransport(stream)) as client:
            answer = await self._answer(client, RequestLimits())

        assert answer.response.status_code == 200
        assert answer.body == b'{"ok": true}'

    async def test_a_request_that_outlives_the_limit_is_refused_as_a_timeout(self) -> None:
        """A step limit bounds one read, so only this bounds a response that arrives slowly in many steps."""
        async with self._client(_SleepingTransport()) as client:
            with pytest.raises(httpx.TimeoutException):
                await self._answer(client, RequestLimits(connect_seconds=0.01, request_seconds=0.01))

    async def test_a_body_that_arrives_slowly_is_refused_within_the_same_limit(self) -> None:
        """The response arrives before its body does, so a limit that ends at the headers bounds no body."""
        stream = LazyByteStream([b"f" * 16] * 100, chunk_seconds=0.05)

        async with self._client(LazyBodyTransport(stream)) as client:
            with pytest.raises(httpx.TimeoutException):
                await self._answer(client, RequestLimits(connect_seconds=0.1, request_seconds=0.2))

    async def test_the_refusal_is_classified_as_a_timeout(self) -> None:
        async with self._client(_SleepingTransport()) as client:
            with pytest.raises(httpx.TimeoutException) as refusal:
                await self._answer(client, RequestLimits(connect_seconds=0.01, request_seconds=0.01))

        assert http_failure(refusal.value) == (FailureKind.TIMEOUT, "request timed out")

    async def test_another_failure_is_left_alone(self) -> None:
        async with self._client(_RefusingTransport(httpx.ConnectError("refused"))) as client:
            with pytest.raises(httpx.ConnectError):
                await self._answer(client, RequestLimits())

    async def test_the_response_is_closed_once_its_body_is_read(self) -> None:
        """A streamed response holds the connection until it is closed."""
        stream = LazyByteStream([b'{"ok": true}'])

        async with self._client(LazyBodyTransport(stream)) as client:
            answer = await self._answer(client, RequestLimits())

        assert answer.response.is_closed

    async def test_the_response_is_closed_when_the_body_passes_the_limit(self) -> None:
        """A body past the limit is abandoned part way, so nothing reaches the end of it to close it."""
        stream = LazyByteStream([b"x" * 64] * 200)

        async with self._client(LazyBodyTransport(stream)) as client:
            answer = await self._answer(client, RequestLimits(max_body_bytes=128))

            assert answer.body is None
            assert answer.response.is_closed
            assert stream.closed

    async def test_a_body_split_into_many_chunks_is_held_in_what_the_limit_allows(self) -> None:
        """The other side chooses how it splits a body, so a bound per chunk is no bound at all."""
        cap = 64 * 1024
        stream = LazyByteStream([b"x"] * cap)

        async with self._client(LazyBodyTransport(stream)) as client:
            tracemalloc.start()
            answer = await self._answer(client, RequestLimits(max_body_bytes=cap))
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        assert answer.body == b"x" * cap
        assert peak < cap * _CHUNK_OVERHEAD_ALLOWED

    async def test_the_response_is_closed_when_the_limit_interrupts_the_read(self) -> None:
        """A body still arriving when the limit passes is abandoned part way for the same reason.

        The refusal states no response, so the response is read from the transport that answered with it.
        """
        stream = LazyByteStream([b"y" * 16] * 100, chunk_seconds=0.05)
        transport = LazyBodyTransport(stream)

        async with self._client(transport) as client:
            with pytest.raises(httpx.TimeoutException):
                await self._answer(client, RequestLimits(connect_seconds=0.1, request_seconds=0.2))

            assert transport.answered[0].is_closed
            assert stream.closed


class TestEveryClientTheLibraryBuildsStatesItsLimits:
    def test_no_request_path_builds_a_client_outside_the_limits(self) -> None:
        """A client built with limits of its own, or with none, is a request path the limits do not reach."""
        outside = []
        for path in sorted(_SRC.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name not in _CLIENTS:
                    continue
                stated = next((keyword.value for keyword in node.keywords if keyword.arg == "timeout"), None)
                in_force = isinstance(stated, ast.Call) and getattr(stated.func, "id", "") == "httpx_timeout"
                if not in_force:
                    outside.append(f"{path.relative_to(_SRC)}:{node.lineno}")

        assert outside == []


class TestEveryRequestIsBoundedAsAWhole:
    def test_no_request_is_awaited_where_nothing_bounds_it(self) -> None:
        """A client's own limits bound one step each, so a request awaited where it is made is unbounded.

        NOTE: This sees a request awaited at the point it is made. It cannot see one stored and awaited
        later, nor a send inside a third-party client, such as authlib's own token request.
        """
        unbounded = [
            f"{path.relative_to(_SRC)}:{node.value.lineno}"
            for path in sorted(_SRC.rglob("*.py"))
            for node in _sends_of_the_librarys_own(path)
            if isinstance(node, ast.Await)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr in _SENDERS
        ]

        assert unbounded == []


class TestEveryBodyIsReadUnderTheLimit:
    def test_no_request_given_to_a_bounded_await_reads_its_body_as_it_is_made(self) -> None:
        """A client's own sender reads the whole body before it answers, so the limit on one never applies.

        The whole-request limit still bounds such a request in time, which is why the other guards stay
        green for it, and that is what makes this one its own check rather than a case of theirs.
        """
        read_as_made = []
        for path in sorted(_SRC.rglob("*.py")):
            for node in _sends_of_the_librarys_own(path):
                if not isinstance(node, ast.Call) or getattr(node.func, "id", "") not in _BOUNDED_AWAITS:
                    continue
                read_as_made += [
                    f"{path.relative_to(_SRC)}:{given.lineno}"
                    for given in node.args
                    if isinstance(given, ast.Call)
                    and isinstance(given.func, ast.Attribute)
                    and given.func.attr in _SENDERS
                ]

        assert read_as_made == []

    def test_no_request_is_sent_outside_the_one_sender_that_leaves_the_body_unread(self) -> None:
        """One function sends, so there is one place a request can be sent without leaving its body unread."""
        sent_elsewhere = [
            f"{path.relative_to(_SRC)}:{node.lineno}"
            for path in sorted(_SRC.rglob("*.py"))
            for node in _sends_of_the_librarys_own(path)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "send"
        ]

        assert sent_elsewhere == []


class TestEveryBuilderTakesTheLimits:
    def test_every_configuration_builder_takes_the_callers_limits(self) -> None:
        """A builder added later is where this is missed, and its users can then set no limit at all."""
        missing = []
        for path in sorted(_SRC.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.FunctionDef) or node.col_offset:
                    continue
                if node.name not in _CONFIG_BUILDERS:
                    continue
                if not any(argument.arg == "limits" for argument in node.args.kwonlyargs):
                    missing.append(f"{path.relative_to(_SRC)}:{node.name}")

        assert missing == []

    def test_a_preset_carries_the_limits_onto_the_configuration(self) -> None:
        limits = RequestLimits(request_seconds=30.0)

        config = google.preset("client", "secret", scopes=["openid"], limits=limits)  # pragma: allowlist secret

        assert config.limits == limits

    def test_a_preset_defaults_to_the_standard_limits(self) -> None:
        config = google.preset("client", "secret", scopes=["openid"])  # pragma: allowlist secret

        assert config.limits == RequestLimits()
