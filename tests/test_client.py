from __future__ import annotations

import time
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from pydantic import SecretStr

from apron_auth.client import OAuthClient
from apron_auth.errors import (
    ConfigurationError,
    PermanentOAuthError,
    RevocationError,
    StateError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import OAuthPendingState, ProviderConfig, TokenSet


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


class TestExchangeCode:
    async def test_exchange_with_direct_params(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "access-abc",
                "token_type": "Bearer",
                "refresh_token": "refresh-xyz",
                "expires_in": 3600,
                "scope": "openid email",
            },
        )
        config = _make_config()
        client = OAuthClient(config=config)
        tokens = await client.exchange_code(
            code="auth-code-123",
            redirect_uri="https://app.example.com/callback",
        )
        assert isinstance(tokens, TokenSet)
        assert tokens.access_token == "access-abc"
        assert tokens.refresh_token == "refresh-xyz"
        assert tokens.expires_in == 3600
        assert tokens.expires_at is not None
        assert tokens.scope == "openid email"

    async def test_exchange_with_pkce(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_config()
        client = OAuthClient(config=config)
        await client.exchange_code(
            code="auth-code-123",
            redirect_uri="https://app.example.com/callback",
            code_verifier="test-verifier",
        )
        request = httpx_mock.get_request()
        assert b"code_verifier=test-verifier" in request.content

    async def test_exchange_with_state_store(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        pending = OAuthPendingState(
            state="stored-state",
            redirect_uri="https://app.example.com/callback",
            code_verifier="stored-verifier",
            created_at=time.time(),
        )
        store = AsyncMock()
        store.consume = AsyncMock(return_value=pending)
        config = _make_config()
        client = OAuthClient(config=config, state_store=store)
        tokens = await client.exchange_code(code="auth-code-123", state="stored-state")
        store.consume.assert_awaited_once_with("stored-state")
        assert tokens.access_token == "access-abc"

    async def test_exchange_state_not_found_raises(self):
        store = AsyncMock()
        store.consume = AsyncMock(return_value=None)
        config = _make_config()
        client = OAuthClient(config=config, state_store=store)
        with pytest.raises(StateError):
            await client.exchange_code(code="auth-code-123", state="bad-state")

    async def test_exchange_token_endpoint_error(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "invalid_grant", "error_description": "Code expired"},
        )
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(TokenExchangeError):
            await client.exchange_code(
                code="bad-code",
                redirect_uri="https://app.example.com/callback",
            )

    async def test_exchange_extra_fields_in_token_set(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "access-abc",
                "token_type": "Bearer",
                "team_id": "T123",
                "authed_user": {"id": "U456"},
            },
        )
        config = _make_config()
        client = OAuthClient(config=config)
        tokens = await client.exchange_code(
            code="auth-code-123",
            redirect_uri="https://app.example.com/callback",
        )
        assert tokens.metadata["team_id"] == "T123"
        assert tokens.metadata["authed_user"] == {"id": "U456"}

    async def test_exchange_client_secret_post(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_config(token_endpoint_auth_method="client_secret_post")
        client = OAuthClient(config=config)
        await client.exchange_code(
            code="auth-code-123",
            redirect_uri="https://app.example.com/callback",
        )
        request = httpx_mock.get_request()
        assert b"client_id=test-client" in request.content
        assert b"client_secret=test-secret" in request.content

    async def test_exchange_client_secret_basic(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_config(token_endpoint_auth_method="client_secret_basic")
        client = OAuthClient(config=config)
        await client.exchange_code(
            code="auth-code-123",
            redirect_uri="https://app.example.com/callback",
        )
        request = httpx_mock.get_request()
        assert request.headers.get("authorization", "").startswith("Basic ")


class TestRefreshToken:
    async def test_successful_refresh(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "new-access",
                "token_type": "Bearer",
                "refresh_token": "new-refresh",
                "expires_in": 3600,
            },
        )
        config = _make_config()
        client = OAuthClient(config=config)
        tokens = await client.refresh_token(refresh_token="old-refresh")
        assert tokens.access_token == "new-access"
        assert tokens.refresh_token == "new-refresh"

    async def test_refresh_sends_correct_grant_type(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "new-access", "token_type": "Bearer"},
        )
        config = _make_config()
        client = OAuthClient(config=config)
        await client.refresh_token(refresh_token="old-refresh")
        request = httpx_mock.get_request()
        assert b"grant_type=refresh_token" in request.content
        assert b"refresh_token=old-refresh" in request.content

    async def test_refresh_permanent_error_invalid_grant(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "invalid_grant", "error_description": "Token revoked"},
        )
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(PermanentOAuthError, match="invalid_grant"):
            await client.refresh_token(refresh_token="revoked-refresh")

    async def test_refresh_permanent_error_unauthorized_client(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=401,
            json={"error": "unauthorized_client"},
        )
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(PermanentOAuthError):
            await client.refresh_token(refresh_token="bad-refresh")

    async def test_refresh_permanent_error_invalid_client(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=401,
            json={"error": "invalid_client"},
        )
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(PermanentOAuthError):
            await client.refresh_token(refresh_token="bad-refresh")

    async def test_refresh_transient_error(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=500,
            json={"error": "server_error"},
        )
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(TokenRefreshError):
            await client.refresh_token(refresh_token="some-refresh")

    async def test_refresh_network_error(self, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(TokenRefreshError):
            await client.refresh_token(refresh_token="some-refresh")

    async def test_refresh_custom_permanent_error_code(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "token_revoked", "error_description": "Token was revoked"},
        )
        config = _make_config()
        client = OAuthClient(config=config, permanent_error_codes={"token_revoked"})
        with pytest.raises(PermanentOAuthError, match="token_revoked"):
            await client.refresh_token(refresh_token="revoked-refresh")

    async def test_refresh_custom_codes_preserve_defaults(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "invalid_grant", "error_description": "Token expired"},
        )
        config = _make_config()
        client = OAuthClient(config=config, permanent_error_codes={"custom_error"})
        with pytest.raises(PermanentOAuthError, match="invalid_grant"):
            await client.refresh_token(refresh_token="expired-refresh")


class TestRevokeToken:
    async def test_successful_revocation(self, httpx_mock):
        from apron_auth.protocols import StandardRevocationHandler

        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=200)
        config = _make_config(revocation_url="https://provider.example.com/revoke")
        handler = StandardRevocationHandler()
        client = OAuthClient(config=config, revocation_handler=handler)
        result = await client.revoke_token(token="access-token")
        assert result is True

    async def test_revocation_no_url_raises(self):
        config = _make_config(revocation_url=None)
        client = OAuthClient(config=config)
        with pytest.raises(ConfigurationError, match="revocation_url"):
            await client.revoke_token(token="access-token")

    async def test_revocation_with_default_handler(self, httpx_mock):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=200)
        config = _make_config(revocation_url="https://provider.example.com/revoke")
        client = OAuthClient(config=config)
        result = await client.revoke_token(token="access-token")
        assert result is True

    async def test_revocation_failure_raises(self, httpx_mock):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=503)
        config = _make_config(revocation_url="https://provider.example.com/revoke")
        client = OAuthClient(config=config)
        with pytest.raises(RevocationError):
            await client.revoke_token(token="access-token")

    async def test_revocation_handler_exception_wrapped(self):
        class BrokenHandler:
            async def revoke(self, token: str, config) -> bool:
                msg = "something unexpected"
                raise RuntimeError(msg)

        config = _make_config(revocation_url="https://provider.example.com/revoke")
        client = OAuthClient(config=config, revocation_handler=BrokenHandler())
        with pytest.raises(RevocationError, match="something unexpected") as exc_info:
            await client.revoke_token(token="access-token")
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    async def test_revocation_error_not_double_wrapped(self):
        class ErrorHandler:
            async def revoke(self, token: str, config) -> bool:
                raise RevocationError("handler error")

        config = _make_config(revocation_url="https://provider.example.com/revoke")
        client = OAuthClient(config=config, revocation_handler=ErrorHandler())
        with pytest.raises(RevocationError, match="handler error") as exc_info:
            await client.revoke_token(token="access-token")
        assert exc_info.value.__cause__ is None
