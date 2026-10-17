"""An asyncio lock that follows the running event loop."""

from __future__ import annotations

import asyncio
import weakref


class LoopLock:
    """Hand out an ``asyncio.Lock`` for the running event loop, replacing one made for an earlier loop.

    Only the latest loop's lock is kept, so at most one finished loop stays in memory.
    One holder may therefore serve callers on different event loops in turn.

    NOTE: Callers must not use one instance from event loops in several threads at once, because it is unguarded.
    """

    def __init__(self) -> None:
        self._lock: asyncio.Lock | None = None
        self._loop: weakref.ref[asyncio.AbstractEventLoop] | None = None

    def __call__(self) -> asyncio.Lock:
        """Return the lock for the running event loop."""
        loop = asyncio.get_running_loop()
        if self._lock is None or self._loop is None or self._loop() is not loop:
            self._lock, self._loop = asyncio.Lock(), weakref.ref(loop)
        return self._lock
