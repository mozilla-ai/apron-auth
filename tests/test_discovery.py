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
    """Return the name a class reference uses, for a bare name or a qualified one."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _calls_the_check(tree: ast.Module) -> bool:
    """Say whether ``tree`` calls the issuer check by the name it is defined with."""
    return any(
        isinstance(node, ast.Call) and _class_name(node.func) == require_declared_issuer.__name__
        for node in ast.walk(tree)
    )


def _imports_the_check(tree: ast.Module) -> bool:
    """Say whether ``tree`` imports the issuer check, under its own name or another."""
    return any(
        alias.name == require_declared_issuer.__name__
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    )


def _modules_where(predicate: Callable[[ast.Module], bool]) -> set[str]:
    """Return the library modules whose syntax tree satisfies ``predicate``."""
    return {
        path.relative_to(SRC).as_posix() for path in sorted(SRC.rglob("*.py")) if predicate(ast.parse(path.read_text()))
    }


class TestTheIssuerRefusalStaysInternal:
    """The refusal is not one of the library's errors, so reaching it commits a module to translating it.

    Each module allowed to reach it has its own tests pinning the error, the message and the kind it raises.
    These assertions keep every other module from raising it.
    """

    def test_only_the_translating_modules_call_the_check(self) -> None:
        assert SRC.is_dir()
        assert _modules_where(_calls_the_check) == ISSUER_CHECK_CALLERS

    def test_no_other_module_reaches_the_check(self) -> None:
        assert _modules_where(_imports_the_check) == ISSUER_CHECK_CALLERS

    def test_the_refusal_is_not_published(self) -> None:
        assert not hasattr(apron_auth, IssuerNotDeclaredError.__name__)
        assert IssuerNotDeclaredError.__name__ not in apron_auth.__all__
