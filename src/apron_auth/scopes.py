"""OAuth scope parsing, formatting, and implicit-scope utilities."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


def resolve_implicit_scopes(granted: set[str], implicit_scopes: dict[str, frozenset[str]]) -> set[str]:
    """Return ``granted`` scopes, expanded with every scope it transitively implies.

    ``implicit_scopes`` maps a scope to the scopes it implies. Each granted
    scope contributes itself plus the scopes it implies, applied transitively
    — if ``a`` implies ``b`` and ``b`` implies ``c``, then granting ``a``
    yields ``a``, ``b``, and ``c``. A cyclic map still terminates.

    The input is not mutated. An empty ``granted``, an empty
    ``implicit_scopes``, or scopes that imply nothing yield an unchanged copy.

    Args:
        granted: The scopes to expand.
        implicit_scopes: A map from each scope to the scopes it implies.

    Returns:
        A new set: ``granted`` plus every scope it transitively implies.
    """
    explicit = set(granted)
    pending = list(granted)
    while pending:
        for implied in implicit_scopes.get(pending.pop(), frozenset()):
            # The membership check both deduplicates and keeps the walk
            # terminating if the map ever contains a cycle.
            if implied not in explicit:
                explicit.add(implied)
                pending.append(implied)
    return explicit


def join_scopes(scopes: list[str], separator: str = " ") -> str:
    """Join scopes into a single delimited string.

    Args:
        scopes: The scopes to join.
        separator: The delimiter placed between adjacent scopes.

    Returns:
        The scopes joined by ``separator``, or an empty string when ``scopes``
        is empty.
    """
    return separator.join(scopes)


def parse_scope(scope: str | list[str], separator: str = " ") -> list[str]:
    """Parse scopes from a string or list into a list.

    Args:
        scope: A delimited scope string, or an already-split list of scopes.
        separator: The delimiter to split a string ``scope`` on.

    Returns:
        The individual scopes with surrounding whitespace stripped and empty
        entries dropped. A list ``scope`` is returned unchanged.

    Raises:
        ValueError: If ``separator`` is empty and ``scope`` is a string that is not blank.
    """
    if isinstance(scope, list):
        return scope
    if not scope or not scope.strip():
        return []
    return [s.strip() for s in scope.split(separator) if s.strip()]


def scope_words(values: Iterable[str], separator: str = " ") -> set[str]:
    """Return every scope word the given scope values carry.

    A scope word is delimited by whitespace (RFC 6749 section 3.3), a comma, or ``separator``.
    Reading a wider set of delimiters finds a word in more strings, which is the safe direction
    for a caller deciding whether a request asks for a scope.

    NOTE: An empty ``separator`` is ignored rather than splitting every character into its own
    word, which would find no scope at all.

    Args:
        values: The scope values to read, each holding one or more words.
        separator: A further delimiter the provider joins its scopes with.

    Returns:
        The words, without the delimiters that separated them.
    """
    delimiters = {",", separator} - {""}
    words: set[str] = set()
    for value in values:
        spaced = value
        for delimiter in delimiters:
            spaced = spaced.replace(delimiter, " ")
        words.update(spaced.split())
    return words
