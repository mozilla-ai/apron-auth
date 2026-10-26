"""The authorization-request parameters are computed in one place, so every reader gets one answer."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

import apron_auth
from apron_auth._authorization_params import authorization_query, scope_param, sent_scope_words
from apron_auth.models import ProviderConfig

_PACKAGE_ROOT = Path(apron_auth.__file__).parent

# The module that reads a URL's query, and the only one allowed to parse one.
_OWNING_MODULE = "_urls.py"


def _config(**overrides: object) -> ProviderConfig:
    """Return a provider configuration with the given overrides."""
    fields: dict[str, object] = {
        "client_id": "cid",
        "client_secret": SecretStr("csecret"),  # pragma: allowlist secret
        "authorize_url": "https://sso.example.com/auth",
        "token_url": "https://sso.example.com/token",
    }
    fields.update(overrides)
    return ProviderConfig(**fields)  # type: ignore[arg-type]


class TestTheScopeParameter:
    def test_the_configured_scopes_are_joined_with_the_separator(self) -> None:
        config = _config(scopes=["openid", "email"], scope_separator=",")
        assert scope_param(config) == {"scope": "openid,email"}

    def test_no_scopes_set_no_parameter(self) -> None:
        """A request that asks for nothing must not state an empty scope."""
        assert scope_param(_config(scopes=[])) == {}


class TestThePrecedenceOfEachSource:
    def test_the_request_parameters_replace_the_authorization_urls_own_query(self) -> None:
        config = _config(authorize_url="https://sso.example.com/auth?scope=openid")

        query = authorization_query(config, {"scope": "email"})

        assert query["scope"] == "email"

    def test_the_extra_parameters_replace_the_request_parameters(self) -> None:
        config = _config(extra_params={"scope": "email"})

        query = authorization_query(config, {"scope": "openid"})

        assert query["scope"] == "email"

    def test_the_resource_replaces_an_extra_parameter_of_the_same_name(self) -> None:
        """RFC 8707 makes the resource authoritative for audience binding."""
        config = _config(resource="https://api.example.com", extra_params={"team": "T1"})

        query = authorization_query(config, {})

        assert query["resource"] == "https://api.example.com"

    def test_the_authorization_urls_own_query_is_kept_where_nothing_replaces_it(self) -> None:
        config = _config(authorize_url="https://sso.example.com/auth?prompt=consent")

        query = authorization_query(config, {"scope": "openid"})

        assert query["prompt"] == "consent"

    def test_a_repeated_parameter_keeps_every_value(self) -> None:
        config = _config(authorize_url="https://sso.example.com/auth?ui_locales=en&ui_locales=fr")

        query = authorization_query(config, {})

        assert query["ui_locales"] == ["en", "fr"]


class TestTheReservedParameters:
    @pytest.mark.parametrize("name", ["client_id", "nonce", "redirect_uri", "request", "state"])
    def test_a_reserved_parameter_is_dropped_from_the_authorization_urls_own_query(self, name: str) -> None:
        """A validated config cannot hold one, so the drop is what protects a config built without validation."""
        config = ProviderConfig.model_construct(
            client_id="cid",
            client_secret=SecretStr("csecret"),  # pragma: allowlist secret
            authorize_url=f"https://sso.example.com/auth?{name}=injected",
            token_url="https://sso.example.com/token",
            scopes=[],
            extra_params={},
            resource=None,
        )

        query = authorization_query(config, {})

        assert name not in query

    @pytest.mark.parametrize("query", ["state=", "state"], ids=["an empty value", "no value at all"])
    def test_a_reserved_parameter_with_no_value_is_dropped_too(self, query: str) -> None:
        config = ProviderConfig.model_construct(
            client_id="cid",
            client_secret=SecretStr("csecret"),  # pragma: allowlist secret
            authorize_url=f"https://sso.example.com/auth?{query}",
            token_url="https://sso.example.com/token",
            scopes=[],
            extra_params={},
            resource=None,
        )

        assert "state" not in authorization_query(config, {})

    @pytest.mark.parametrize("name", ["client_id", "nonce", "redirect_uri", "request", "state"])
    def test_a_reserved_parameter_is_dropped_from_the_extra_parameters(self, name: str) -> None:
        config = ProviderConfig.model_construct(
            client_id="cid",
            client_secret=SecretStr("csecret"),  # pragma: allowlist secret
            authorize_url="https://sso.example.com/auth",
            token_url="https://sso.example.com/token",
            scopes=[],
            extra_params={name: "injected"},
            resource=None,
        )

        query = authorization_query(config, {})

        assert name not in query


class TestTheScopeWordsOfASentParameter:
    def test_a_single_value_is_read(self) -> None:
        assert sent_scope_words({"scope": "openid email"}, "scope", " ") == {"openid", "email"}

    def test_several_values_are_read(self) -> None:
        assert sent_scope_words({"scope": ["openid", "email"]}, "scope", " ") == {"openid", "email"}

    def test_a_parameter_that_is_absent_carries_no_words(self) -> None:
        assert sent_scope_words({}, "scope", " ") == set()

    def test_each_scope_parameter_is_read_on_its_own(self) -> None:
        """A provider that splits bot and user scopes states them in parameters of their own."""
        query: dict[str, str | list[str]] = {"scope": "channels:read", "user_scope": "openid"}

        assert sent_scope_words(query, "user_scope", ",") == {"openid"}


def test_only_the_owning_module_parses_a_url_query() -> None:
    """Two parsers of a query disagree as soon as one of them changes, so there is one parser."""
    readers = sorted(
        path.name for path in _PACKAGE_ROOT.rglob("*.py") if "parse_qs" in path.read_text(encoding="utf-8")
    )

    assert readers == [_OWNING_MODULE]
