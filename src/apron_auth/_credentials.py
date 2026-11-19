"""The rule that decides how a credential may reach this library."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import SecretStr

from apron_auth.errors import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable


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


def _supplied_as_plain_text(wrapper: type[SecretStr]) -> str:
    """Return what a refusal tells the caller to do, which no value of theirs appears in.

    The wrapper is named rather than described, because a refusal naming one the field then refuses
    sends the caller to a second refusal about something else.

    Args:
        wrapper: The type the value has to arrive in.

    Returns:
        The refusal text, without the name of what is being refused.
    """
    return (
        f"must be wrapped in {wrapper.__name__}, because a plain string stays in a frame local "
        "that an error reporter records"
    )


def arrives_wrapped(wrapper: type[SecretStr]) -> Callable[[Any], Any]:
    """Return the rule a model field of ``wrapper`` states about how its credential arrives.

    A credential bound to a parameter or to a validated mapping is a frame local for the whole call,
    which an error reporter reading frame locals off a traceback records. A wrapper states nothing in
    its own ``repr``, so wrapping is what keeps the credential out of the record.

    The rule refuses the value rather than wrapping it, because wrapping it at this point leaves the
    plain string bound in every frame it already passed through.

    Args:
        wrapper: The type the field's credential has to arrive in.

    Returns:
        A validator that hands back the value it was given, and refuses a plain string stating a
        credential.
    """

    def rule(value: Any) -> Any:
        if _states_a_credential_as_plain_text(value):
            raise ValueError(_supplied_as_plain_text(wrapper))
        return value

    return rule


def refuse_plain_text(value: Any, field: str, wrapper: type[SecretStr]) -> None:
    """Refuse a credential supplied as plain text to a parameter no model validates.

    Every string is refused here, including one holding no non-blank character. A field reads what a
    value states, because a blank one converts to a wrapper holding nothing, and a client secret
    stating nothing is a public client. A parameter converts nothing, so a blank string is a value of
    the wrong type rather than a credential stating nothing, and the code that reads it would fail
    where the value is used instead of where it was passed.

    Args:
        value: The value a caller passed.
        field: The parameter's name, for the refusal to name.
        wrapper: The type the parameter's credential has to arrive in.

    Raises:
        ConfigurationError: If the value is a plain string.
    """
    if isinstance(value, str):
        msg = f"{field} {_supplied_as_plain_text(wrapper)}"
        raise ConfigurationError(msg)
