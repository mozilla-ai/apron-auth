"""OAuth scope parsing and formatting utilities."""

from __future__ import annotations


def parse_scope(scope: str | list[str], separator: str = " ") -> list[str]:
    """Parse scopes from a string or list into a list.

    Handles space-separated, comma-separated, and pre-split list inputs.
    """
    if isinstance(scope, list):
        return scope
    if not scope or not scope.strip():
        return []
    return [s.strip() for s in scope.split(separator) if s.strip()]


def join_scopes(scopes: list[str], separator: str = " ") -> str:
    """Join a list of scopes into a single string."""
    return separator.join(scopes)
