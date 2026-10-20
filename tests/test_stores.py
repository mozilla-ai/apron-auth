from __future__ import annotations

import logging
import math
import time
from types import SimpleNamespace

import pytest

from apron_auth._clock import CLOCK_SKEW_SECONDS
from apron_auth.errors import ConfigurationError
from apron_auth.models import OAuthPendingState
from apron_auth.protocols import StateStore
from apron_auth.stores import MemoryStateStore


def _freeze_store_clock(monkeypatch: pytest.MonkeyPatch, now: float) -> None:
    """Pin the clock the expiry rule reads to ``now``.

    NOTE: The stub exposes only ``time.time``, so any other clock the rule reads raises in the test.
    """
    monkeypatch.setattr("apron_auth._clock.time", SimpleNamespace(time=lambda: now))


def _make_pending(state: str = "test-state", age: float = 0.0) -> OAuthPendingState:
    return OAuthPendingState(
        state=state,
        redirect_uri="https://app.example.com/callback",
        code_verifier="test-verifier",
        created_at=time.time() - age,
    )


class TestMemoryStateStore:
    def test_satisfies_state_store_protocol(self):
        assert isinstance(MemoryStateStore(), StateStore)

    async def test_save_and_consume_returns_state(self):
        store = MemoryStateStore()
        pending = _make_pending()
        await store.save(pending)
        result = await store.consume(pending.state)
        assert result == pending

    async def test_consume_removes_state(self):
        store = MemoryStateStore()
        pending = _make_pending()
        await store.save(pending)
        await store.consume(pending.state)
        result = await store.consume(pending.state)
        assert result is None

    async def test_consume_unknown_key_returns_none(self):
        store = MemoryStateStore()
        result = await store.consume("nonexistent")
        assert result is None

    async def test_consume_expired_state_returns_none(self):
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(age=301.0)
        await store.save(pending)
        result = await store.consume(pending.state)
        assert result is None

    async def test_consume_state_at_boundary_returns_state(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A state whose age is exactly the limit is still current, and only one past it is not."""
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(age=300.0)
        await store.save(pending)
        # The clock is frozen, because the microseconds a live clock advances would carry the age past the limit.
        _freeze_store_clock(monkeypatch, pending.created_at + 300.0)

        assert await store.consume(pending.state) == pending

    async def test_consume_state_past_the_boundary_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(age=300.0)
        await store.save(pending)
        _freeze_store_clock(monkeypatch, pending.created_at + 300.001)

        assert await store.consume(pending.state) is None

    async def test_consume_a_state_at_the_clock_difference_ahead_returns_state(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A creation time the allowed clock difference ahead is still current, because clocks differ."""
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending()
        await store.save(pending)
        _freeze_store_clock(monkeypatch, pending.created_at - CLOCK_SKEW_SECONDS)

        assert await store.consume(pending.state) == pending

    async def test_consume_a_state_past_the_clock_difference_ahead_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending()
        await store.save(pending)
        _freeze_store_clock(monkeypatch, pending.created_at - CLOCK_SKEW_SECONDS - 0.001)

        assert await store.consume(pending.state) is None

    async def test_consume_fresh_state_returns_state(self):
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(age=299.0)
        await store.save(pending)
        result = await store.consume(pending.state)
        assert result == pending

    async def test_save_prunes_expired_entries(self):
        store = MemoryStateStore(max_age=300.0)
        old = _make_pending(state="old", age=301.0)
        await store.save(old)
        fresh = _make_pending(state="fresh", age=0.0)
        await store.save(fresh)
        assert await store.consume("old") is None
        assert await store.consume("fresh") == fresh

    async def test_custom_max_age(self):
        store = MemoryStateStore(max_age=60.0)
        pending = _make_pending(age=61.0)
        await store.save(pending)
        assert await store.consume(pending.state) is None

    async def test_default_max_age_is_ten_minutes(self):
        store = MemoryStateStore()
        pending = _make_pending(age=601.0)
        await store.save(pending)
        assert await store.consume(pending.state) is None

        fresh = _make_pending(state="fresh", age=599.0)
        await store.save(fresh)
        assert await store.consume(fresh.state) == fresh


class TestCreationTimeThatCannotBeMeasured:
    """Test that a creation time no clock produced expires the entry instead of raising."""

    @pytest.mark.parametrize(
        "created_at",
        [
            pytest.param(10**400, id="beyond the float range"),
            pytest.param(math.inf, id="infinite"),
            pytest.param(-math.inf, id="negatively infinite"),
            pytest.param(math.nan, id="not a number"),
        ],
    )
    async def test_an_unusable_creation_time_expires_the_entry(self, created_at: float) -> None:
        store = MemoryStateStore(max_age=300.0)
        pending = OAuthPendingState.model_construct(
            state="test-state",
            redirect_uri="https://app.example.com/callback",
            code_verifier="test-verifier",
            created_at=created_at,
        )
        await store.save(pending)

        assert await store.consume(pending.state) is None

    async def test_the_pruning_scan_drops_the_entry_and_keeps_the_store_usable(self) -> None:
        """One unusable entry must not take the whole store down, because every save scans them all."""
        store = MemoryStateStore(max_age=300.0)
        unusable = OAuthPendingState.model_construct(
            state="unusable-state",
            redirect_uri="https://app.example.com/callback",
            code_verifier="test-verifier",
            created_at=10**400,
        )
        await store.save(unusable)

        fresh = _make_pending(state="fresh")
        await store.save(fresh)

        assert await store.consume(fresh.state) == fresh
        assert await store.consume(unusable.state) is None

    async def test_a_creation_time_ahead_of_the_clock_expires_the_entry(self) -> None:
        """A creation time further ahead of the clock than the allowed difference is not current."""
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(age=-3600.0)
        await store.save(pending)

        assert await store.consume(pending.state) is None


class TestExpiryLogLine:
    """Test that dropping an entry reports why without carrying any value from the entry."""

    async def test_the_line_carries_no_value_at_all(self, caplog: pytest.LogCaptureFixture) -> None:
        """The whole line is asserted, because a value can reach it however the message is built."""
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(state="s3cr3t-state-key-value", age=301.0)
        await store.save(pending)

        with caplog.at_level(logging.DEBUG, logger="apron_auth.stores"):
            assert await store.consume(pending.state) is None

        assert [record.getMessage() for record in caplog.records] == [
            "Dropped a pending authorization request that is no longer current"
        ]

    async def test_the_pruning_scan_reports_what_it_dropped(self, caplog: pytest.LogCaptureFixture) -> None:
        """The scan drops entries nobody looked up, so the count is the only record that it happened."""
        store = MemoryStateStore(max_age=300.0)
        await store.save(_make_pending(state="s3cr3t-state-key-value", age=301.0))

        with caplog.at_level(logging.DEBUG, logger="apron_auth.stores"):
            await store.save(_make_pending(state="fresh"))

        assert [record.getMessage() for record in caplog.records] == [
            "Dropped pending authorization requests that are no longer current: count=1"
        ]


class TestMaximumAgeArgument:
    """Test that a limit that is not a positive finite number is refused where it is set."""

    @pytest.mark.parametrize(
        "max_age",
        [
            pytest.param(10**400, id="beyond the float range"),
            pytest.param(math.inf, id="infinite"),
            pytest.param(math.nan, id="not a number"),
            pytest.param(None, id="absent"),
            pytest.param("600", id="a string"),
            pytest.param(0.0, id="zero"),
            pytest.param(-1.0, id="negative"),
        ],
    )
    def test_a_limit_that_is_not_a_positive_finite_number_is_refused(self, max_age: object) -> None:
        with pytest.raises(ConfigurationError, match="positive finite number"):
            MemoryStateStore(max_age=max_age)

    async def test_a_usable_limit_is_accepted(self) -> None:
        store = MemoryStateStore(max_age=1.0)
        pending = _make_pending()
        await store.save(pending)

        assert await store.consume(pending.state) == pending
