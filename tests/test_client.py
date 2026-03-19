from __future__ import annotations

import time
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import pytest
from pydantic import SecretStr

from any_auth.client import OAuthClient
from any_auth.errors import ConfigurationError
from any_auth.models import OAuthPendingState, ProviderConfig, TokenSet


def _make_config(**overrides: object) -> ProviderConfig:
    defaults = {
        "client_id": "test-client",
        "client_secret": SecretStr("test-secret"),
        "authorize_url": "https://provider.example.com/authorize",
        "token_url": "https://provider.example.com/token",
        "scopes": ["openid", "email"],
    }
    defaults.update(overrides)
    return ProviderConfig(**defaults)


class TestGetAuthorizationUrl:
    async def test_returns_url_and_pending_state(self):
        config = _make_config()
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        assert url.startswith("https://provider.example.com/authorize?")
        assert isinstance(pending_state, OAuthPendingState)
        assert pending_state.redirect_uri == "https://app.example.com/callback"

    async def test_url_contains_required_params(self):
        config = _make_config()
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["test-client"]
        assert params["response_type"] == ["code"]
        assert params["redirect_uri"] == ["https://app.example.com/callback"]
        assert params["scope"] == ["openid email"]
        assert "state" in params

    async def test_pkce_included_when_enabled(self):
        config = _make_config(use_pkce=True)
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["code_challenge_method"] == ["S256"]
        assert "code_challenge" in params
        assert pending_state.code_verifier is not None

    async def test_pkce_excluded_when_disabled(self):
        config = _make_config(use_pkce=False)
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert "code_challenge" not in params
        assert pending_state.code_verifier is None

    async def test_extra_params_included(self):
        config = _make_config(extra_params={"access_type": "offline", "prompt": "consent"})
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["access_type"] == ["offline"]
        assert params["prompt"] == ["consent"]

    async def test_scope_separator_applied(self):
        config = _make_config(scopes=["read", "write"], scope_separator=",")
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["scope"] == ["read,write"]

    async def test_redirect_uri_from_config(self):
        config = _make_config(redirect_uri="https://app.example.com/default-callback")
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url()
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["redirect_uri"] == ["https://app.example.com/default-callback"]
        assert pending_state.redirect_uri == "https://app.example.com/default-callback"

    async def test_method_redirect_uri_overrides_config(self):
        config = _make_config(redirect_uri="https://app.example.com/default")
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/override",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["redirect_uri"] == ["https://app.example.com/override"]
        assert pending_state.redirect_uri == "https://app.example.com/override"

    async def test_no_redirect_uri_raises(self):
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(ConfigurationError, match="redirect_uri"):
            await client.get_authorization_url()

    async def test_state_store_save_called(self):
        config = _make_config()
        store = AsyncMock()
        store.save = AsyncMock()
        client = OAuthClient(config=config, state_store=store)
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        store.save.assert_awaited_once()
        saved_state = store.save.call_args[0][0]
        assert saved_state.state == pending_state.state

    async def test_state_store_not_called_when_absent(self):
        config = _make_config()
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        assert pending_state is not None

    async def test_state_is_unique_per_call(self):
        config = _make_config()
        client = OAuthClient(config=config)
        _, s1 = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        _, s2 = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        assert s1.state != s2.state
