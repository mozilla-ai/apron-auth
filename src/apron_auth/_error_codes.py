"""The shape a token-endpoint error code takes."""

from __future__ import annotations

import re

# A token-endpoint error code: a lowercase identifier, in one word or several joined by underscores.
_CODE_PATTERN = re.compile(r"[a-z]+(?:_[a-z0-9]+)*")

# The greatest length, in characters, of a code this library reads. The longest code any registry
# defines is 32 characters, so this bound admits every registered code and separates nothing on its own.
_MAX_CODE_LENGTH = 64


def recognized_error_code(value: object) -> str:
    """Return the token-endpoint error code when ``value`` states one in the shape a code takes.

    RFC 6749 section 5.2 names six codes and then restricts only the characters the field may hold,
    so a response can carry anything printable there, including a value the request sent.
    Every code the registries define, and every code a provider defines of its own, is a lowercase
    identifier, which the hex, base32 and URL-safe forms a credential takes are not.
    A value of another shape, or one longer than any code, is not comparable against a known code,
    so it is reported as absent.

    Args:
        value: The ``error`` member of a token endpoint's response, as it arrived.

    Returns:
        The code, or an empty string when the value states none in the shape a code takes.
    """
    if not isinstance(value, str) or len(value) > _MAX_CODE_LENGTH:
        return ""
    return value if _CODE_PATTERN.fullmatch(value) else ""
