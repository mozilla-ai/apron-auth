from __future__ import annotations

from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth import (
    ConfigurationError,
    MemoryStateStore,
    OAuthClient,
    OAuthError,
    OAuthPendingState,
    PermanentOAuthError,
    ProviderConfig,
    RevocationError,
    RevocationHandler,
    StandardRevocationHandler,
    StateError,
    StateStore,
    TokenExchangeError,
    TokenRefreshError,
    TokenSet,
)


class TestFullOAuthFlow:
    async def test_authorization_exchange_refresh_revoke(self, httpx_mock: HTTPXMock):
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            revocation_url="https://provider.example.com/revoke",
            scopes=["openid", "email"],
            use_pkce=True,
        )
        store = MemoryStateStore()
        handler = StandardRevocationHandler()
        client = OAuthClient(config=config, state_store=store, revocation_handler=handler)

        # Step 1: Build authorization URL.
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        assert "provider.example.com/authorize" in url
        assert pending_state.code_verifier is not None
        assert pending_state.state in store._states

        # Step 2: Exchange code via state store.
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "access-token-abc",
                "token_type": "Bearer",
                "refresh_token": "refresh-token-xyz",
                "expires_in": 3600,
                "scope": "openid email",
            },
        )
        tokens = await client.exchange_code(
            code="authorization-code",
            state=pending_state.state,
        )
        assert tokens.access_token == "access-token-abc"
        assert tokens.refresh_token == "refresh-token-xyz"
        assert tokens.expires_at is not None
        assert pending_state.state not in store._states

        # Step 3: Refresh token.
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "new-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )
        refreshed = await client.refresh_token(refresh_token=tokens.refresh_token)
        assert refreshed.access_token == "new-access-token"

        # Step 4: Revoke token.
        httpx_mock.add_response(
            url="https://provider.example.com/revoke",
            status_code=200,
        )
        result = await client.revoke_token(token=refreshed.access_token)
        assert result is True


class TestMetadataFlowsThroughStateStore:
    async def test_metadata_survives_save_and_consume(self, httpx_mock: HTTPXMock):
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            scopes=["openid"],
            use_pkce=True,
        )
        store = MemoryStateStore()
        client = OAuthClient(config=config, state_store=store)

        meta = {"user_id": "U123", "tenant_id": "T456", "tool_name": "slack"}
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
            metadata=meta,
        )
        assert pending_state.metadata == meta

        # Consume from store and verify metadata survived round-trip.
        consumed = await store.consume(pending_state.state)
        assert consumed is not None
        assert consumed.metadata == meta
        assert consumed.metadata["user_id"] == "U123"

    async def test_metadata_flows_through_to_token_set_context(self, httpx_mock: HTTPXMock):
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            scopes=["openid"],
            use_pkce=True,
        )
        store = MemoryStateStore()
        client = OAuthClient(config=config, state_store=store)

        meta = {"user_id": "U123", "tenant_id": "T456"}
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
            metadata=meta,
        )

        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "access-token-abc",
                "token_type": "Bearer",
                "team_id": "T-provider",
            },
        )
        tokens = await client.exchange_code(
            code="authorization-code",
            state=pending_state.state,
        )
        assert tokens.context == meta
        assert tokens.context["user_id"] == "U123"
        assert tokens.metadata["team_id"] == "T-provider"


class TestSlackUserScopesInAuthorizationUrl:
    async def test_user_scope_appears_in_url(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="slack-id",
            client_secret="slack-secret",  # pragma: allowlist secret
            scopes=["channels:read"],
            user_scopes=["users:read", "channels:history"],
        )
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        from urllib.parse import parse_qs, urlparse

        params = parse_qs(urlparse(url).query)
        assert params["user_scope"] == ["users:read,channels:history"]
        assert params["scope"] == ["channels:read"]


class TestPublicApiExports:
    def test_all_public_types_importable(self):
        assert OAuthClient is not None
        assert ProviderConfig is not None
        assert TokenSet is not None
        assert OAuthPendingState is not None
        assert StateStore is not None
        assert MemoryStateStore is not None
        assert RevocationHandler is not None
        assert StandardRevocationHandler is not None
        assert OAuthError is not None
        assert TokenExchangeError is not None
        assert TokenRefreshError is not None
        assert PermanentOAuthError is not None
        assert RevocationError is not None
        assert StateError is not None
        assert ConfigurationError is not None

    def test_provider_presets_importable(self):
        from apron_auth.providers import (
            atlassian,
            github,
            google,
            hubspot,
            linear,
            microsoft,
            notion,
            salesforce,
            slack,
            typeform,
        )

        for module in (atlassian, github, google, hubspot, linear, microsoft, notion, salesforce, slack, typeform):
            assert callable(module.preset)
