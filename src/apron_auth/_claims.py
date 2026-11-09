"""The shape a claim about an identity takes, where a provider states one."""

from __future__ import annotations


def stated_boolean(value: object) -> bool | None:
    """Return the boolean a provider stated, or ``None`` where it stated none this library can read.

    A response body and a token claim are both untrusted input, and nothing in either shape holds a
    member to the type its documentation names. Coercing the value instead would read the string
    ``"false"`` as ``True``, which asserts the opposite of what the provider wrote, so a value of any
    other type states nothing rather than something.

    Args:
        value: The member or claim as it arrived.

    Returns:
        The boolean the provider stated, or ``None`` where it stated a value of another type or none
        at all.
    """
    return value if isinstance(value, bool) else None
