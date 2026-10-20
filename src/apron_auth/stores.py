"""Reference StateStore implementations."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apron_auth._clock import DEFAULT_MAX_AGE_SECONDS, pending_age_refusal, usable_max_age
from apron_auth.errors import ConfigurationError

if TYPE_CHECKING:
    from apron_auth.models import OAuthPendingState

logger = logging.getLogger(__name__)


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

    A state is expired when its creation time is past ``max_age``, lies further ahead of the
    system clock than the allowed difference, or cannot be measured at all.
    """

    def __init__(self, max_age: float = DEFAULT_MAX_AGE_SECONDS) -> None:
        """Create the store.

        Args:
            max_age: The age, in seconds, past which a stored state is treated as expired.

        Raises:
            ConfigurationError: If ``max_age`` is not a positive number of seconds
                that can be subtracted from a clock reading.
        """
        limit = usable_max_age(max_age)
        if limit is None:
            msg = "max_age must be a positive number of seconds that can be subtracted from a clock reading"
            raise ConfigurationError(msg)
        self._states: dict[str, OAuthPendingState] = {}
        self._max_age = limit

    async def save(self, state: OAuthPendingState) -> None:
        """Store pending state and prune any expired entries.

        Args:
            state: The pending state to store.
        """
        self._prune()
        self._states[state.state] = state

    async def consume(self, state_key: str) -> OAuthPendingState | None:
        """Retrieve and remove state, returning None if expired or missing.

        Args:
            state_key: The state token to retrieve and remove.

        Returns:
            The stored state, or ``None`` when it is missing or expired.
        """
        pending = self._states.pop(state_key, None)
        if pending is None:
            return None
        if self._is_expired(pending):
            # NOTE: A state key identifies one user's authorization attempt, so no part of it is logged.
            logger.debug("Dropped a pending authorization request that is no longer current")
            return None
        return pending

    def _is_expired(self, state: OAuthPendingState) -> bool:
        """Report whether ``state`` is no longer current against the system clock.

        Args:
            state: The pending state to test.

        Returns:
            ``True`` when the creation time fails any of the clock conditions for a pending request.
        """
        return pending_age_refusal(state.created_at, max_age=self._max_age) is not None

    def _prune(self) -> None:
        """Drop every stored state that has expired, reporting how many were dropped."""
        expired_keys = [k for k, v in self._states.items() if self._is_expired(v)]
        for key in expired_keys:
            del self._states[key]
        if expired_keys:
            logger.debug(
                "Dropped pending authorization requests that are no longer current: count=%d", len(expired_keys)
            )
