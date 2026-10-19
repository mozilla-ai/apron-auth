"""Every error this library raises says what went wrong.

A handler outside the library may leave ``kind`` out and get ``UNEXPECTED``.
Library code may not: each construction of an error that can fail in several ways names its kind,
and each token refusal names its reason.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from apron_auth import errors

SRC = Path(__file__).resolve().parents[1] / "src" / "apron_auth"
MULTI_KIND = {
    cls.__name__
    for cls in vars(errors).values()
    if isinstance(cls, type) and issubclass(cls, errors.OAuthError) and cls.default_kind is None
}
# A helper that raises a caller-chosen class must pass the kind through as well.
MULTI_KIND.add("error_cls")


def _called_name(func: ast.expr) -> str | None:
    """Return the name a call targets, for a bare name or a qualified one such as ``errors.X``."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _unclassified_calls(path: Path) -> list[str]:
    """Return ``file:line`` for each error construction in ``path`` that names no kind or no reason."""
    found = []
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Call):
            continue
        name = _called_name(node.func)
        keywords = {keyword.arg for keyword in node.keywords}
        if name in MULTI_KIND and "kind" not in keywords:
            found.append(f"{path.name}:{node.lineno}")
        if name == "TokenValidationError" and "reason" not in keywords:
            found.append(f"{path.name}:{node.lineno}")
    return found


@pytest.mark.parametrize("path", sorted(SRC.rglob("*.py")), ids=lambda p: str(p.relative_to(SRC)))
def test_every_library_raise_names_its_kind(path: Path) -> None:
    assert _unclassified_calls(path) == []


def test_the_guard_sees_a_missing_kind(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    lines = [
        "raise IdentityFetchError('x')",
        "failure = RevocationError('y', kind=k)",
        "TokenValidationError('z')",
        "raise errors.McpDiscoveryError('q')",
        "raise errors.McpDiscoveryError('q', kind=k)",
    ]
    sample.write_text("\n".join(lines) + "\n")
    assert _unclassified_calls(sample) == ["sample.py:1", "sample.py:3", "sample.py:4"]
