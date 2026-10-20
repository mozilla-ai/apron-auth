"""Reference StateStore implementations."""

from __future__ import annotations

import logging
import sys
import time
from typing import TYPE_CHECKING

from apron_auth._jwt import CLOCK_SKEW_SECONDS
from apron_auth._numbers import finite_number
from apron_auth.errors import ConfigurationError

if TYPE_CHECKING:
    from apron_auth.models import OAuthPendingState

logger = logging.getLogger(__name__)

# The default age, in seconds, after which a stored pending state expires.
DEFAULT_MAX_AGE = 600.0

# The widest maximum age, in seconds, the system clock can be offset by.
_WIDEST_MAX_AGE = sys.float_info.max


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
    A state exactly ``max_age`` old is still current, which is where the code exchange draws the line too.
    """

    def __init__(self, max_age: float = DEFAULT_MAX_AGE) -> None:
        """Create the store.

        Args:
            max_age: The age, in seconds, past which a stored state is treated as expired.
                A state exactly this old is still current.

        Raises:
            ConfigurationError: If ``max_age`` is not a positive finite number, because no stored state
                would ever reach a limit it cannot be compared against.
        """
        if finite_number(max_age) is None or max_age <= 0 or max_age > _WIDEST_MAX_AGE:
            msg = "max_age must be a positive finite number"
            raise ConfigurationError(msg)
        self._states: dict[str, OAuthPendingState] = {}
        self._max_age = max_age

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

        The creation time is compared against thresholds taken from the clock, so a value outside the
        float range is answered rather than raising. A creation time further ahead of the clock than the
        allowed difference is not current either, because no nearby clock produced it.

        Args:
            state: The pending state to test.

        Returns:
            ``True`` when the creation time is not a finite number, lies too far ahead of the clock,
            or is older than ``max_age``.
        """
        created_at = finite_number(state.created_at)
        if created_at is None:
            return True
        now = time.time()
        return created_at > now + CLOCK_SKEW_SECONDS or created_at < now - self._max_age

    def _prune(self) -> None:
        """Drop every stored state that has expired."""
        expired_keys = [k for k, v in self._states.items() if self._is_expired(v)]
        for key in expired_keys:
            del self._states[key]
