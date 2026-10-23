from __future__ import annotations

import pytest

from apron_auth.scopes import join_scopes, parse_scope, resolve_implicit_scopes, scope_words

# Synthetic implicit-scope map used to exercise the helper independently of
# any provider's real data: ``a`` -> ``b`` -> ``c`` is a transitive chain and
# ``x`` implies two leaves.
_IMPLICIT: dict[str, frozenset[str]] = {
    "a": frozenset({"b"}),
    "b": frozenset({"c"}),
    "x": frozenset({"y", "z"}),
}


class TestResolveImplicitScopes:
    @pytest.mark.parametrize(
        ("granted", "implicit_scopes", "expected"),
        [
            # A single implied scope is made explicit.
            ({"x"}, _IMPLICIT, {"x", "y", "z"}),
            # Implications are followed transitively along a chain.
            ({"a"}, _IMPLICIT, {"a", "b", "c"}),
            # Entering a chain partway resolves only the remaining tail.
            ({"b"}, _IMPLICIT, {"b", "c"}),
            # Independent granted scopes resolve independently in one call.
            ({"a", "x"}, _IMPLICIT, {"a", "b", "c", "x", "y", "z"}),
            # A leaf scope that implies nothing is returned unchanged.
            ({"c"}, _IMPLICIT, {"c"}),
            # An unknown scope is returned unchanged.
            ({"unknown"}, _IMPLICIT, {"unknown"}),
            # An empty map leaves the input unchanged.
            ({"a"}, {}, {"a"}),
            # An empty granted set returns empty.
            (set(), _IMPLICIT, set()),
        ],
    )
    def test_resolves_transitive_implications(
        self, granted: set[str], implicit_scopes: dict[str, frozenset[str]], expected: set[str]
    ) -> None:
        assert resolve_implicit_scopes(granted, implicit_scopes) == expected

    def test_does_not_mutate_input(self) -> None:
        granted = {"a"}
        resolve_implicit_scopes(granted, _IMPLICIT)
        assert granted == {"a"}

    def test_returns_new_set_object(self) -> None:
        granted = {"c"}
        assert resolve_implicit_scopes(granted, _IMPLICIT) is not granted

    def test_terminates_on_cyclic_map(self) -> None:
        # A malformed (cyclic) map must not loop forever; the closure
        # still resolves to the full reachable set.
        cyclic = {"p": frozenset({"q"}), "q": frozenset({"p"})}
        assert resolve_implicit_scopes({"p"}, cyclic) == {"p", "q"}


class TestJoinScopes:
    def test_space_join(self) -> None:
        assert join_scopes(["openid", "email"]) == "openid email"

    def test_comma_join(self) -> None:
        assert join_scopes(["read", "write"], separator=",") == "read,write"

    def test_empty(self) -> None:
        assert join_scopes([]) == ""

    def test_single(self) -> None:
        assert join_scopes(["openid"]) == "openid"


class TestParseScope:
    def test_space_separated(self) -> None:
        assert parse_scope("openid email profile") == ["openid", "email", "profile"]

    def test_comma_separated(self) -> None:
        assert parse_scope("read,write,admin", separator=",") == ["read", "write", "admin"]

    def test_already_list(self) -> None:
        assert parse_scope(["openid", "email"]) == ["openid", "email"]

    def test_empty_string(self) -> None:
        assert parse_scope("") == []

    def test_empty_list(self) -> None:
        assert parse_scope([]) == []

    def test_strips_whitespace(self) -> None:
        assert parse_scope(" openid  email ") == ["openid", "email"]

    def test_comma_with_spaces(self) -> None:
        assert parse_scope("read, write, admin", separator=",") == ["read", "write", "admin"]

    def test_single_scope(self) -> None:
        assert parse_scope("openid") == ["openid"]

    def test_an_empty_separator_is_refused(self) -> None:
        # The parser adds no check of its own, so the split is what refuses an empty separator.
        with pytest.raises(ValueError):
            parse_scope("openid email", separator="")

    @pytest.mark.parametrize("scope", ["", "   "], ids=["empty", "blank"])
    def test_an_empty_separator_does_not_refuse_a_blank_scope(self, scope: str) -> None:
        assert parse_scope(scope, separator="") == []


class TestScopeWords:
    """The words a scope value carries, which decide whether a request asks for a scope."""

    @pytest.mark.parametrize(
        ("values", "separator", "expected"),
        [
            pytest.param(["openid email"], " ", {"openid", "email"}, id="split on a space"),
            pytest.param(["openid,email"], ",", {"openid", "email"}, id="split on the separator"),
            pytest.param(["openid,email"], " ", {"openid", "email"}, id="a comma is always a delimiter"),
            pytest.param(["openid email"], ",", {"openid", "email"}, id="whitespace is always a delimiter"),
            pytest.param(["openid", "email"], ",", {"openid", "email"}, id="several values"),
            pytest.param(["  openid  "], ",", {"openid"}, id="surrounding whitespace is dropped"),
            pytest.param([""], ",", set(), id="an empty value carries no word"),
            pytest.param([], ",", set(), id="no values"),
            pytest.param(["openid:read"], ",", {"openid:read"}, id="a colon does not delimit"),
        ],
    )
    def test_the_words_a_value_carries(self, values: list[str], separator: str, expected: set[str]) -> None:
        assert scope_words(values, separator) == expected

    def test_an_empty_separator_is_ignored_rather_than_splitting_every_character(self) -> None:
        """Splitting on an empty string would find no scope at all, which is the unsafe direction."""
        assert scope_words(["openid email"], separator="") == {"openid", "email"}
