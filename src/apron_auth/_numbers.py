"""Guards for a number that arrived from outside this library."""

from __future__ import annotations

import math


def finite_number(value: object) -> int | float | None:
    """Return ``value`` when it is a finite number, else ``None``.

    A boolean is not a number here, and an integer is always finite, however large.

    Args:
        value: The value to check, which may be of any type.

    Returns:
        The number, or ``None`` when it is not one or is not finite.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value
