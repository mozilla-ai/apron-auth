from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import httpx
import pytest

from apron_auth._http_errors import http_failure
from apron_auth._timeouts import httpx_timeout, within_request_limit
from apron_auth.errors import FailureKind
from apron_auth.models import TimeoutPolicy
from apron_auth.providers import google

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


class TestWithinRequestLimit:
    async def test_a_request_that_finishes_in_time_answers_normally(self) -> None:
        async def answer() -> str:
            return "answered"

        assert await within_request_limit(answer(), TimeoutPolicy()) == "answered"

    async def test_a_request_that_outlives_the_limit_is_refused_as_a_timeout(self) -> None:
        """A step limit bounds one read, so only this bounds a response that arrives slowly in many steps."""

        async def never() -> str:
            await asyncio.sleep(60)
            return "answered"

        with pytest.raises(httpx.TimeoutException):
            await within_request_limit(never(), TimeoutPolicy(request_seconds=0.01))

    async def test_the_refusal_is_classified_as_a_timeout(self) -> None:
        async def never() -> str:
            await asyncio.sleep(60)
            return "answered"

        with pytest.raises(httpx.TimeoutException) as refusal:
            await within_request_limit(never(), TimeoutPolicy(request_seconds=0.01))

        assert http_failure(refusal.value) == (FailureKind.TIMEOUT, "request timed out")

    async def test_another_failure_is_left_alone(self) -> None:
        async def refuse() -> str:
            raise httpx.ConnectError("refused")

        with pytest.raises(httpx.ConnectError):
            await within_request_limit(refuse(), TimeoutPolicy())


class TestEveryClientTheLibraryBuildsStatesItsLimits:
    def test_no_request_path_builds_a_client_without_limits(self) -> None:
        """A client built without limits bounds nothing, and a request path added later is where that is missed."""
        unbounded = []
        for path in sorted(_SRC.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name not in {"AsyncClient", "AsyncOAuth2Client"}:
                    continue
                if not any(keyword.arg == "timeout" for keyword in node.keywords):
                    unbounded.append(f"{path.relative_to(_SRC)}:{node.lineno}")

        assert unbounded == []


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
