"""The rule that decides how a credential may reach this library."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import SecretStr

from apron_auth.errors import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable


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
        f"must be wrapped in {wrapper.__name__}, because a credential outside it stays in a frame "
        "local that an error reporter records"
    )


def arrives_wrapped(wrapper: type[SecretStr]) -> Callable[[Any], Any]:
    """Return the rule a model field of ``wrapper`` states about how its credential arrives.

    A credential bound to a parameter or to a validated mapping is a frame local for the whole call,
    which an error reporter reading frame locals off a traceback records. A wrapper states nothing in
    its own ``repr``, so wrapping is what keeps the credential out of the record.

    The rule refuses the value rather than wrapping it, because wrapping it at this point leaves the
    plain string bound in every frame it already passed through.

    Every string is refused, including one holding no non-blank character. A field whose credential
    may be absent reads what a value states before this rule runs, so a client secret stating nothing
    arrives here as absence rather than as a blank string.

    A secret wrapper the field does not state is refused in the same words, because a caller who
    reads the refusal and reaches for the other of the two wrappers would otherwise be answered by
    the validation framework in terms of its own.

    Anything else is handed on, because what a stated credential may be is the field's own type to
    decide.

    Args:
        wrapper: The type the field's credential has to arrive in.

    Returns:
        A validator that hands back the value it was given, and refuses one the field cannot hold.
    """

    def rule(value: Any) -> Any:
        if isinstance(value, str) or (isinstance(value, SecretStr) and not isinstance(value, wrapper)):
            raise ValueError(_supplied_as_plain_text(wrapper))
        return value

    return rule


def refuse_plain_text(value: Any, field: str, wrapper: type[SecretStr]) -> None:
    """Refuse a credential supplied as plain text to a parameter no model validates.

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
