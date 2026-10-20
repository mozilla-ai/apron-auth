from __future__ import annotations

import logging
import math
import time

import pytest

from apron_auth import stores
from apron_auth.models import OAuthPendingState
from apron_auth.protocols import StateStore
from apron_auth.stores import MemoryStateStore


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

    async def test_consume_state_at_boundary_returns_state(self, monkeypatch: pytest.MonkeyPatch):
        """Exactly the limit is still current, which is where the code exchange draws the line too."""
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(age=300.0)
        await store.save(pending)
        # The clock is frozen, because the microseconds a live clock advances would carry the age past the limit.
        monkeypatch.setattr(stores.time, "time", lambda: pending.created_at + 300.0)

        assert await store.consume(pending.state) == pending

    async def test_consume_state_past_the_boundary_returns_none(self, monkeypatch: pytest.MonkeyPatch):
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(age=300.0)
        await store.save(pending)
        monkeypatch.setattr(stores.time, "time", lambda: pending.created_at + 300.001)

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

    async def test_a_creation_time_ahead_of_the_clock_expires_the_entry(self) -> None:
        """A stamp no nearby clock produced is unusable, as the code exchange also treats it."""
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(age=-3600.0)
        await store.save(pending)

        assert await store.consume(pending.state) is None


class TestExpiryLogLine:
    """Test that dropping an entry reports why without carrying the state it dropped."""

    async def test_the_line_carries_no_part_of_the_state_key(self, caplog: pytest.LogCaptureFixture) -> None:
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(state="s3cr3t-state-key-value", age=301.0)
        await store.save(pending)

        with caplog.at_level(logging.DEBUG, logger="apron_auth.stores"):
            assert await store.consume(pending.state) is None

        assert caplog.text
        for length in range(4, len(pending.state) + 1):
            assert pending.state[:length] not in caplog.text
