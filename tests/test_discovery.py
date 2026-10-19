from __future__ import annotations

import pytest

from apron_auth._discovery import IssuerNotDeclaredError, IssuerRefusalReason, require_declared_issuer, str_list


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
