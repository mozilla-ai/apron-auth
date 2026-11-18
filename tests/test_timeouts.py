from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import httpx
import pytest
from support import LazyBodyTransport, LazyByteStream

from apron_auth._http_errors import http_failure
from apron_auth._timeouts import BoundedResponse, httpx_timeout, within_request_limit
from apron_auth.errors import FailureKind
from apron_auth.models import TimeoutPolicy
from apron_auth.providers import google

# The HTTP clients this library builds, each of which states the policy's per-step limits.
_CLIENTS = {"AsyncClient", "AsyncOAuth2Client"}

# The client methods that send a request.
_SENDERS = {"fetch_token", "get", "post", "request", "send"}

# The functions that build a provider configuration, each of which a caller states its limits through.
_CONFIG_BUILDERS = {"preset", "sign_in_preset", "to_provider_config"}

# The library's source tree, walked to keep every request path bounded.
_SRC = Path(__file__).resolve().parents[1] / "src" / "apron_auth"


class TestHttpxTimeout:
    def test_every_step_of_a_request_is_bounded(self) -> None:
        limits = httpx_timeout(TimeoutPolicy(connect_seconds=2.0, request_seconds=7.0))

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
    async def _answer(client: httpx.AsyncClient, policy: TimeoutPolicy) -> BoundedResponse:
        request = client.build_request("GET", "https://documents.test/d")
        return await within_request_limit(client.send(request, stream=True), policy)

    async def test_a_request_that_finishes_in_time_answers_normally(self) -> None:
        stream = LazyByteStream([b'{"ok": true}'])

        async with self._client(LazyBodyTransport(stream)) as client:
            answer = await self._answer(client, TimeoutPolicy())

        assert answer.response.status_code == 200
        assert answer.body == b'{"ok": true}'
        assert answer.complete

    async def test_a_request_that_outlives_the_limit_is_refused_as_a_timeout(self) -> None:
        """A step limit bounds one read, so only this bounds a response that arrives slowly in many steps."""
        async with self._client(_SleepingTransport()) as client:
            with pytest.raises(httpx.TimeoutException):
                await self._answer(client, TimeoutPolicy(connect_seconds=0.01, request_seconds=0.01))

    async def test_a_body_that_arrives_slowly_is_refused_within_the_same_limit(self) -> None:
        """The response arrives before its body does, so a limit that ends at the headers bounds no body."""
        stream = LazyByteStream([b"f" * 16] * 100, chunk_seconds=0.05)

        async with self._client(LazyBodyTransport(stream)) as client:
            with pytest.raises(httpx.TimeoutException):
                await self._answer(client, TimeoutPolicy(connect_seconds=0.1, request_seconds=0.2))

    async def test_the_refusal_is_classified_as_a_timeout(self) -> None:
        async with self._client(_SleepingTransport()) as client:
            with pytest.raises(httpx.TimeoutException) as refusal:
                await self._answer(client, TimeoutPolicy(connect_seconds=0.01, request_seconds=0.01))

        assert http_failure(refusal.value) == (FailureKind.TIMEOUT, "request timed out")

    async def test_another_failure_is_left_alone(self) -> None:
        async with self._client(_RefusingTransport(httpx.ConnectError("refused"))) as client:
            with pytest.raises(httpx.ConnectError):
                await self._answer(client, TimeoutPolicy())

    async def test_the_response_is_closed_once_its_body_is_read(self) -> None:
        """A streamed response holds the connection until it is closed."""
        stream = LazyByteStream([b'{"ok": true}'])

        async with self._client(LazyBodyTransport(stream)) as client:
            answer = await self._answer(client, TimeoutPolicy())

        assert answer.response.is_closed


class TestEveryClientTheLibraryBuildsStatesItsLimits:
    def test_no_request_path_builds_a_client_outside_the_policy(self) -> None:
        """A client built with limits of its own, or with none, is a request path the policy does not reach."""
        outside = []
        for path in sorted(_SRC.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name not in _CLIENTS:
                    continue
                limits = next((keyword.value for keyword in node.keywords if keyword.arg == "timeout"), None)
                from_the_policy = isinstance(limits, ast.Call) and getattr(limits.func, "id", "") == "httpx_timeout"
                if not from_the_policy:
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
            for node in ast.walk(ast.parse(path.read_text()))
            if isinstance(node, ast.Await)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr in _SENDERS
        ]

        assert unbounded == []


class TestEveryBodyIsReadUnderTheLimit:
    def test_no_request_is_sent_where_its_body_arrives_before_the_limit_applies(self) -> None:
        """A send that is not streamed reads the whole body before returning, so no cap can reach it."""
        unstreamed = []
        for path in sorted(_SRC.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr != "send":
                    continue
                streamed = next((keyword.value for keyword in node.keywords if keyword.arg == "stream"), None)
                if not (isinstance(streamed, ast.Constant) and streamed.value is True):
                    unstreamed.append(f"{path.relative_to(_SRC)}:{node.lineno}")

        assert unstreamed == []


class TestEveryBuilderTakesThePolicy:
    def test_every_configuration_builder_takes_the_callers_policy(self) -> None:
        """A builder added later is where this is missed, and its users can then set no limit at all."""
        missing = []
        for path in sorted(_SRC.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.FunctionDef) or node.col_offset:
                    continue
                if node.name not in _CONFIG_BUILDERS:
                    continue
                if not any(argument.arg == "timeouts" for argument in node.args.kwonlyargs):
                    missing.append(f"{path.relative_to(_SRC)}:{node.name}")

        assert missing == []

    def test_a_preset_carries_the_policy_onto_the_configuration(self) -> None:
        policy = TimeoutPolicy(request_seconds=30.0)

        config = google.preset("client", "secret", scopes=["openid"], timeouts=policy)  # pragma: allowlist secret

        assert config.timeouts == policy

    def test_a_preset_defaults_to_the_policys_own_limits(self) -> None:
        config = google.preset("client", "secret", scopes=["openid"])  # pragma: allowlist secret

        assert config.timeouts == TimeoutPolicy()
