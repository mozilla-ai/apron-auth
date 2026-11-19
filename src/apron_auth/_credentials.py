"""The rule that decides how a credential may reach this library."""

from __future__ import annotations

from typing import Any

# What a refusal tells the caller to do, which no value of theirs appears in.
_SUPPLIED_AS_PLAIN_TEXT = (
    "must be wrapped in SecretStr or SecretToken, because a plain string stays in a frame local "
    "that an error reporter records"
)


def wrapped_credential(value: Any) -> Any:
    """Return the value, refusing a credential supplied as plain text.

    A credential bound to a parameter or to a validated mapping is a frame local for the whole call,
    which an error reporter reading frame locals off a traceback records. A wrapper states nothing in
    its own ``repr``, so wrapping is what keeps the credential out of the record.

    The value is refused rather than wrapped here, because wrapping it at this point leaves the
    plain string bound in every frame it already passed through.

    A string holding no non-blank character authenticates nothing, so it states no credential and is
    handed back. Whether a stated credential is a value it may be is left to the field's own type.

    Args:
        value: The value to read, as a wrapped credential, as the string one wraps, or as anything a
            caller passed in their place.

    Returns:
        The value as it arrived.

    Raises:
        ValueError: If the value states a credential as a plain string.
    """
    if isinstance(value, str) and value.strip():
        raise ValueError(_SUPPLIED_AS_PLAIN_TEXT)
    return value
