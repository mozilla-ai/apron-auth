"""The clock difference this library allows between hosts, and the age rule for a pending request."""

from __future__ import annotations

import time
from enum import Enum, auto

from apron_auth._numbers import finite_number

# The clock difference, in seconds, allowed between this client and another host wherever a time is checked.
CLOCK_SKEW_SECONDS = 60


class PendingAgeRefusalReason(Enum):
    """Each member is one clock condition a pending authorization request's creation time can fail."""

    # The creation time lies further ahead of this clock than the allowed difference.
    AHEAD_OF_CLOCK = auto()
    # The creation time is older than the maximum age.
    TOO_OLD = auto()
    # The creation time is not a finite number, so no age can be measured from it.
    UNUSABLE = auto()


def pending_age_refusal(created_at: object, *, max_age: float) -> PendingAgeRefusalReason | None:
    """Report which clock condition ``created_at`` fails, or ``None`` when the request is still current.

    A creation time exactly ``max_age`` old is current, and one exactly the allowed clock difference
    ahead of this clock is current, so each limit refuses only what lies past it.

    Args:
        created_at: The creation time, in epoch seconds, as it arrived.
        max_age: The age, in seconds, past which a pending authorization request is no longer current.

    Returns:
        The condition the creation time fails, or ``None`` when it fails none.

    NOTE: Callers must pass a ``max_age`` the clock can be offset by, because a wider one cannot be
    subtracted from a clock reading.
    """
    stamp = finite_number(created_at)
    if stamp is None:
        return PendingAgeRefusalReason.UNUSABLE
    now = time.time()
    if stamp > now + CLOCK_SKEW_SECONDS:
        return PendingAgeRefusalReason.AHEAD_OF_CLOCK
    if stamp < now - max_age:
        return PendingAgeRefusalReason.TOO_OLD
    return None
