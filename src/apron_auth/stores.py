"""Reference StateStore implementations."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apron_auth.models import OAuthPendingState

logger = logging.getLogger(__name__)

DEFAULT_MAX_AGE = 600.0


class MemoryStateStore:
    """In-memory StateStore with automatic expiry of stale entries.

    Suitable for development, CLIs, and single-process deployments.
    Production multi-process deployments should use a shared store
    (e.g. Redis with TTL) instead.

    Expired entries are pruned lazily via an O(n) scan on each save
    call and checked on consume, so no background tasks or timers
    are needed. This is acceptable for typical OAuth flows where the
    number of concurrent pending states is small.

    Methods are async to satisfy the StateStore protocol (which must
    support I/O-backed implementations like Redis); this in-memory
    implementation performs no I/O. Atomicity relies on the absence
    of await points — if an await is ever added to save or consume,
    an asyncio.Lock must be introduced to guard _states.

    Expiry is based on wall-clock time (time.time) to match
    OAuthPendingState.created_at, which stores epoch seconds.
    A state is considered expired when its age >= max_age.
    """

    def __init__(self, max_age: float = DEFAULT_MAX_AGE) -> None:
        self._states: dict[str, OAuthPendingState] = {}
        self._max_age = max_age

    async def save(self, state: OAuthPendingState) -> None:
        """Store pending state and prune any expired entries."""
        self._prune()
        self._states[state.state] = state

    async def consume(self, state_key: str) -> OAuthPendingState | None:
        """Retrieve and remove state, returning None if expired or missing."""
        pending = self._states.pop(state_key, None)
        if pending is None:
            return None
        if self._is_expired(pending):
            age = time.time() - pending.created_at
            logger.debug(
                "State %.8s… expired (age=%.1fs, max_age=%.1fs)",
                state_key,
                age,
                self._max_age,
            )
            return None
        return pending

    def _is_expired(self, state: OAuthPendingState) -> bool:
        return time.time() - state.created_at >= self._max_age

    def _prune(self) -> None:
        expired_keys = [k for k, v in self._states.items() if self._is_expired(v)]
        for key in expired_keys:
            del self._states[key]
