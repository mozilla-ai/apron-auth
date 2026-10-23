from __future__ import annotations

import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth import (
    ConfigurationError,
    IdentityFetchError,
    IdentityHandler,
    IdentityNotSupportedError,
    IdentityProfile,
    IdTokenValidationError,
    MemoryStateStore,
    NonceValidationError,
    OAuthClient,
    OAuthError,
    OAuthPendingState,
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


def _id_token(nonce: str | None, *, audience: str = "test-client", issuer: str | None = None) -> str:
    """Return a compact token carrying ``nonce``, with a signature nothing here checks."""
    assert nonce, "an OpenID authorization request always carries a nonce"
    claims: dict[str, object] = {"sub": "u-1", "aud": audience, "exp": int(time.time()) + 300, "nonce": nonce}
    if issuer is not None:
        claims["iss"] = issuer
    segments = [{"alg": "RS256"}, claims]
    encoded = [base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b"=").decode() for part in segments]
    return ".".join([*encoded, "c2ln"])


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
                "id_token": _id_token(pending_state.nonce),
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
                "id_token": _id_token(pending_state.nonce),
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

        params = parse_qs(urlparse(url).query)
        assert params["user_scope"] == ["users:read,channels:history"]
        assert params["scope"] == ["channels:read"]


class TestSlackSignInFlow:
    """Sign in with Slack runs on Slack's OpenID endpoints, which are the ones that return an ID token."""

    @staticmethod
    def _client() -> OAuthClient:
        from apron_auth.providers.slack import sign_in_preset

        config, _ = sign_in_preset(
            client_id="slack-id",
            client_secret="slack-secret",  # pragma: allowlist secret
            scopes=["email"],
        )
        return OAuthClient(config=config, state_store=MemoryStateStore())

    async def test_the_authorization_url_is_slacks_openid_endpoint_and_carries_a_nonce(self) -> None:
        client = self._client()

        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )

        params = parse_qs(urlparse(url).query)
        assert url.startswith("https://slack.com/openid/connect/authorize")
        assert params["scope"] == ["openid,email"]
        assert pending_state.nonce is not None
        assert params["nonce"] == [pending_state.nonce]

    async def test_a_token_response_without_an_id_token_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """Slack's install endpoint returns no ID token, so a response without one cannot be signed in with."""
        client = self._client()
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        httpx_mock.add_response(
            url="https://slack.com/api/openid.connect.token",
            json={"ok": True, "access_token": "xoxp-user-token", "token_type": "Bearer"},
        )
        # The client revokes the tokens of a refused response before it raises.
        httpx_mock.add_response(url="https://slack.com/api/auth.revoke", json={"ok": True})

        with pytest.raises(NonceValidationError):
            await client.exchange_code(code="authorization-code", state=pending_state.state)

    async def test_a_token_response_carrying_the_nonce_is_accepted(self, httpx_mock: HTTPXMock) -> None:
        client = self._client()
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        httpx_mock.add_response(
            url="https://slack.com/api/openid.connect.token",
            json={
                "ok": True,
                "access_token": "xoxp-user-token",
                "token_type": "Bearer",
                "id_token": _id_token(pending_state.nonce, audience="slack-id", issuer="https://slack.com"),
            },
        )

        tokens = await client.exchange_code(code="authorization-code", state=pending_state.state)

        assert tokens.access_token == "xoxp-user-token"

    async def test_an_id_token_from_another_issuer_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """The preset names Slack's issuer, so a token minted elsewhere cannot sign a person in."""
        client = self._client()
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        httpx_mock.add_response(
            url="https://slack.com/api/openid.connect.token",
            json={
                "ok": True,
                "access_token": "xoxp-user-token",
                "token_type": "Bearer",
                "id_token": _id_token(pending_state.nonce, audience="slack-id", issuer="https://evil.example.com"),
            },
        )
        # The client revokes the tokens of a refused response before it raises.
        httpx_mock.add_response(url="https://slack.com/api/auth.revoke", json={"ok": True})

        with pytest.raises(IdTokenValidationError):
            await client.exchange_code(code="authorization-code", state=pending_state.state)

    async def test_an_id_token_carrying_another_nonce_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """A replayed ID token carries the nonce of the request it was minted for, not this one."""
        client = self._client()
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        httpx_mock.add_response(
            url="https://slack.com/api/openid.connect.token",
            json={
                "ok": True,
                "access_token": "xoxp-user-token",
                "token_type": "Bearer",
                "id_token": _id_token("another-request-nonce", audience="slack-id", issuer="https://slack.com"),
            },
        )
        # The client revokes the tokens of a refused response before it raises.
        httpx_mock.add_response(url="https://slack.com/api/auth.revoke", json={"ok": True})

        with pytest.raises(NonceValidationError):
            await client.exchange_code(code="authorization-code", state=pending_state.state)


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
        assert RevocationError is not None
        assert StateError is not None
        assert ConfigurationError is not None
        assert IdentityProfile is not None
        assert IdentityHandler is not None
        assert IdentityFetchError is not None
        assert IdentityNotSupportedError is not None

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
