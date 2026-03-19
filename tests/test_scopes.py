from __future__ import annotations

from any_auth.scopes import join_scopes, parse_scope


class TestParseScope:
    def test_space_separated(self):
        assert parse_scope("openid email profile") == ["openid", "email", "profile"]

    def test_comma_separated(self):
        assert parse_scope("read,write,admin", separator=",") == ["read", "write", "admin"]

    def test_already_list(self):
        assert parse_scope(["openid", "email"]) == ["openid", "email"]

    def test_empty_string(self):
        assert parse_scope("") == []

    def test_empty_list(self):
        assert parse_scope([]) == []

    def test_strips_whitespace(self):
        assert parse_scope(" openid  email ") == ["openid", "email"]

    def test_comma_with_spaces(self):
        assert parse_scope("read, write, admin", separator=",") == ["read", "write", "admin"]

    def test_single_scope(self):
        assert parse_scope("openid") == ["openid"]


class TestJoinScopes:
    def test_space_join(self):
        assert join_scopes(["openid", "email"]) == "openid email"

    def test_comma_join(self):
        assert join_scopes(["read", "write"], separator=",") == "read,write"

    def test_empty(self):
        assert join_scopes([]) == ""

    def test_single(self):
        assert join_scopes(["openid"]) == "openid"
