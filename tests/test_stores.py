from __future__ import annotations

import time

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

    async def test_consume_state_at_boundary_returns_none(self):
        store = MemoryStateStore(max_age=300.0)
        pending = _make_pending(age=300.0)
        await store.save(pending)
        result = await store.consume(pending.state)
        assert result is None

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
