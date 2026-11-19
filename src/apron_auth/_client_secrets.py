"""The rule that decides what counts as no client secret."""

from __future__ import annotations

from typing import Any

from pydantic import SecretStr


def stated_client_secret(value: Any) -> Any:
    """Return the client secret a value states, or ``None`` where it states none.

    A client secret is the string it holds, so a wrapper is read for its value rather than trusted
    for its presence.
    A wrapper holding nothing renders as an empty secret, which reads as a secret that is present
    and blank rather than one that was never supplied.
    A string holding no non-blank character states no secret either, because it authenticates no client.

    Whether a value that states something is a string it can state is left to the field's own type,
    so this decides presence alone.

    Args:
        value: The value to read, as a secret, as the string one wraps, or as ``None``.

    Returns:
        The value a present secret states, or ``None`` where it states none.
    """
    held = value.get_secret_value() if isinstance(value, SecretStr) else value
    if held is None or (isinstance(held, str) and not held.strip()):
        return None
    return held
