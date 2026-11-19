"""The rule that decides what counts as no client secret."""

from __future__ import annotations

from typing import Any

from pydantic import SecretStr


def stated_client_secret(value: Any) -> Any:
    """Return the client secret a value states, or ``None`` where it states none.

    A client secret is the string it holds, so a wrapper is read for its value rather than trusted
    for its presence.
    A string holding no non-blank character states no secret, because it authenticates no client.

    Whether a stated secret is a string it may be is left to the field's own type, so this decides
    presence alone.

    NOTE: A stated secret is returned as it arrived, so a caller asking only whether one is present
    is handed no secret to bind. A wrapper holding no string is unwrapped, because a type that
    trusts the wrapper never sees the value it has to refuse.

    Args:
        value: The value to read, as a secret, as the string one wraps, or as ``None``.

    Returns:
        What the value states, or ``None`` where it states no secret.
    """
    held = value.get_secret_value() if isinstance(value, SecretStr) else value
    if held is None or (isinstance(held, str) and not held.strip()):
        return None
    return value if isinstance(held, str) else held
