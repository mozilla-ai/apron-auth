"""The rule that decides how a credential may reach this library."""

from __future__ import annotations

from typing import Any

from apron_auth.errors import ConfigurationError

# What a refusal tells the caller to do, which no value of theirs appears in.
_SUPPLIED_AS_PLAIN_TEXT = (
    "must be wrapped in SecretStr or SecretToken, because a plain string stays in a frame local "
    "that an error reporter records"
)


def _states_a_credential_as_plain_text(value: Any) -> bool:
    """Report whether a value states a credential and arrived unwrapped.

    A string holding no non-blank character authenticates nothing, so it states no credential.
    Whether a stated credential is a value it may be is left to the type that holds it.

    Args:
        value: The value to read.

    Returns:
        Whether the value is a plain string stating a credential.
    """
    return isinstance(value, str) and bool(value.strip())


def refuse_plain_text(value: Any, field: str) -> None:
    """Refuse a credential supplied as plain text to a parameter no model validates.

    Every string is refused here, including one holding no non-blank character. A field reads what a
    value states, because a blank one converts to a wrapper holding nothing, and a client secret
    stating nothing is a public client. A parameter converts nothing, so a blank string is a value of
    the wrong type rather than a credential stating nothing, and the code that reads it would fail
    where the value is used instead of where it was passed.

    Args:
        value: The value a caller passed.
        field: The parameter's name, for the refusal to name.

    Raises:
        ConfigurationError: If the value is a plain string.
    """
    if isinstance(value, str):
        msg = f"{field} {_SUPPLIED_AS_PLAIN_TEXT}"
        raise ConfigurationError(msg)


def wrapped_credential(value: Any) -> Any:
    """Return the value, refusing a credential supplied as plain text to a model field.

    A credential bound to a parameter or to a validated mapping is a frame local for the whole call,
    which an error reporter reading frame locals off a traceback records. A wrapper states nothing in
    its own ``repr``, so wrapping is what keeps the credential out of the record.

    The value is refused rather than wrapped here, because wrapping it at this point leaves the
    plain string bound in every frame it already passed through.

    Args:
        value: The value to read, as a wrapped credential, as the string one wraps, or as anything a
            caller passed in their place.

    Returns:
        The value as it arrived.

    Raises:
        ValueError: If the value states a credential as a plain string.
    """
    if _states_a_credential_as_plain_text(value):
        raise ValueError(_SUPPLIED_AS_PLAIN_TEXT)
    return value
