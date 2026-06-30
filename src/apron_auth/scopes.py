"""OAuth scope parsing, formatting, and implicit-scope utilities."""

from __future__ import annotations


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

    Handles space-separated, comma-separated, and pre-split list inputs.

    Args:
        scope: A delimited scope string, or an already-split list of scopes.
        separator: The delimiter to split a string ``scope`` on.

    Returns:
        The individual scopes with surrounding whitespace stripped and empty
        entries dropped. A list ``scope`` is returned unchanged.
    """
    if isinstance(scope, list):
        return scope
    if not scope or not scope.strip():
        return []
    return [s.strip() for s in scope.split(separator) if s.strip()]
