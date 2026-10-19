from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import apron_auth
from apron_auth._discovery import IssuerNotDeclaredError, IssuerRefusalReason, require_declared_issuer, str_list

if TYPE_CHECKING:
    from collections.abc import Callable

# The library modules allowed to run the issuer check, each wrapping the refusal in the error for its own phase.
ISSUER_CHECK_CALLERS = {"mcp.py", "providers/_openid_documents.py"}
# The library's source tree, walked to keep the issuer refusal inside it.
SRC = Path(__file__).resolve().parents[1] / "src" / "apron_auth"


class TestStrList:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (["a", "b"], ["a", "b"]),
            (["a", 1, None, "b"], ["a", "b"]),
            ([], []),
            (None, []),
            ("not-a-list", []),
            ({"a": 1}, []),
        ],
    )
    def test_filters_to_strings(self, value: object, expected: list[str]) -> None:
        assert str_list(value) == expected


class TestRequireDeclaredIssuer:
    def test_accepts_the_identical_issuer(self) -> None:
        require_declared_issuer({"issuer": "https://auth.example.com"}, "https://auth.example.com")

    @pytest.mark.parametrize(
        "document",
        [{}, {"issuer": None}, {"issuer": 42}, {"issuer": ""}],
        ids=["absent", "null", "not a string", "empty"],
    )
    def test_refuses_a_document_that_declares_no_issuer(self, document: dict[str, object]) -> None:
        with pytest.raises(IssuerNotDeclaredError) as exc_info:
            require_declared_issuer(document, "https://auth.example.com")
        assert exc_info.value.reason is IssuerRefusalReason.ABSENT

    @pytest.mark.parametrize(
        "issuer",
        ["https://evil.example.com", "https://auth.example.com/", "https://AUTH.example.com"],
        ids=["other host", "terminating slash", "other case"],
    )
    def test_refuses_a_document_that_declares_a_different_issuer(self, issuer: str) -> None:
        """The declared issuer is compared exactly, with no normalization."""
        with pytest.raises(IssuerNotDeclaredError) as exc_info:
            require_declared_issuer({"issuer": issuer}, "https://auth.example.com")
        assert exc_info.value.reason is IssuerRefusalReason.MISMATCHED


def _class_name(node: ast.expr) -> str | None:
    """Return the name a class reference names, for a bare name or a qualified one."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _refusal_handler_spans(tree: ast.Module) -> list[range]:
    """Return the line span of each ``try`` body whose handlers catch the issuer refusal."""
    spans = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        caught = [
            _class_name(value)
            for handler in node.handlers
            if handler.type is not None
            for value in (handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type])
        ]
        if IssuerNotDeclaredError.__name__ in caught:
            last = node.body[-1]
            spans.append(range(node.body[0].lineno, (last.end_lineno or last.lineno) + 1))
    return spans


def _issuer_check_calls(tree: ast.Module) -> list[ast.Call]:
    """Return every call to the issuer check in ``tree``."""
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _class_name(node.func) == require_declared_issuer.__name__
    ]


def _unwrapped_issuer_checks(path: Path) -> list[str]:
    """Return ``file:line`` for each issuer check in ``path`` that no handler for the refusal encloses."""
    tree = ast.parse(path.read_text())
    spans = _refusal_handler_spans(tree)
    return [
        f"{path.name}:{node.lineno}" for node in _issuer_check_calls(tree) if not any(node.lineno in s for s in spans)
    ]


def _modules_where(predicate: Callable[[ast.Module], bool]) -> set[str]:
    """Return the library modules whose syntax tree satisfies ``predicate``."""
    return {
        path.relative_to(SRC).as_posix() for path in sorted(SRC.rglob("*.py")) if predicate(ast.parse(path.read_text()))
    }


def _imports_the_check(tree: ast.Module) -> bool:
    """Say whether ``tree`` imports the issuer check, under its own name or an alias."""
    return any(
        alias.name == require_declared_issuer.__name__
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    )


class TestTheIssuerRefusalIsAlwaysWrapped:
    """The refusal is internal, and only a handler for it keeps it out of the library's public errors.

    NOTE: The guard reads the issuer check and the refusal by the names they are defined under, so a module
    that renamed either on import would be invisible to it. The import allowlist below is what closes that.
    """

    @pytest.mark.parametrize("path", sorted(SRC.rglob("*.py")), ids=lambda p: str(p.relative_to(SRC)))
    def test_every_issuer_check_sits_in_a_handler_for_the_refusal(self, path: Path) -> None:
        assert _unwrapped_issuer_checks(path) == []

    def test_the_guard_sees_a_check_no_handler_covers(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.py"
        lines = [
            "require_declared_issuer(document, expected)",
            "try:",
            "    require_declared_issuer(document, expected)",
            "except IssuerNotDeclaredError:",
            "    pass",
            "try:",
            "    require_declared_issuer(document, expected)",
            "except ValueError:",
            "    pass",
        ]
        sample.write_text("\n".join(lines) + "\n")
        assert _unwrapped_issuer_checks(sample) == ["sample.py:1", "sample.py:7"]

    def test_the_guard_reads_the_call_sites_it_claims_to_cover(self) -> None:
        """Without this the guard above passes by finding nothing at all."""
        assert SRC.is_dir()
        assert _modules_where(lambda tree: bool(_issuer_check_calls(tree))) == ISSUER_CHECK_CALLERS

    def test_no_other_module_reaches_the_check(self) -> None:
        assert _modules_where(_imports_the_check) == ISSUER_CHECK_CALLERS

    def test_the_refusal_is_not_published(self) -> None:
        assert not hasattr(apron_auth, IssuerNotDeclaredError.__name__)
        assert IssuerNotDeclaredError.__name__ not in apron_auth.__all__
