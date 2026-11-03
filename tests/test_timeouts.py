from __future__ import annotations

import asyncio

import httpx
import pytest

from apron_auth._http_errors import http_failure
from apron_auth._timeouts import httpx_timeout, within_request_limit
from apron_auth.errors import FailureKind
from apron_auth.models import TimeoutPolicy


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
