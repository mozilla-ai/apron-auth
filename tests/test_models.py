from __future__ import annotations

import time

import pytest
from pydantic import SecretStr, ValidationError

from apron_auth.models import OAuthPendingState, ProviderConfig, TokenSet


class TestProviderConfig:
    def test_minimal_config(self):
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.client_id == "test-client"
        assert config.client_secret.get_secret_value() == "test-secret"
        assert config.scopes == []
        assert config.scope_separator == " "
        assert config.use_pkce is True
        assert config.token_endpoint_auth_method == "client_secret_post"
        assert config.extra_params == {}
        assert config.revocation_url is None
        assert config.redirect_uri is None

    def test_full_config(self):
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            revocation_url="https://provider.example.com/revoke",
            redirect_uri="https://app.example.com/callback",
            scopes=["read", "write"],
            scope_separator=",",
            use_pkce=False,
            token_endpoint_auth_method="client_secret_basic",
            extra_params={"access_type": "offline"},
        )
        assert config.scope_separator == ","
        assert config.use_pkce is False
        assert config.token_endpoint_auth_method == "client_secret_basic"
        assert config.extra_params == {"access_type": "offline"}

    def test_frozen(self):
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        with pytest.raises(ValidationError):
            config.client_id = "other"

    def test_secret_not_leaked_in_repr(self):
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert "test-secret" not in repr(config)
        assert "test-secret" not in str(config)

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            ProviderConfig(client_id="test")


class TestTokenSet:
    def test_minimal_token(self):
        token = TokenSet(access_token="access-abc")
        assert token.access_token == "access-abc"
        assert token.token_type == "Bearer"
        assert token.refresh_token is None
        assert token.expires_in is None
        assert token.expires_at is None
        assert token.scope is None
        assert token.metadata == {}

    def test_full_token(self):
        token = TokenSet(
            access_token="access-abc",
            token_type="Bearer",
            refresh_token="refresh-xyz",
            expires_in=3600,
            expires_at=1700000000.0,
            scope="read write",
            metadata={"team_id": "T123"},
        )
        assert token.refresh_token == "refresh-xyz"
        assert token.expires_in == 3600
        assert token.metadata == {"team_id": "T123"}

    def test_context_defaults_to_empty_dict(self):
        token = TokenSet(access_token="access-abc")
        assert token.context == {}

    def test_context_round_trips(self):
        ctx = {"user_id": "U123", "tenant_id": "T456"}
        token = TokenSet(access_token="access-abc", context=ctx)
        assert token.context == ctx
        assert token.context["user_id"] == "U123"

    def test_metadata_isolated_from_caller_mutation(self):
        original = {"team_id": "T123"}
        token = TokenSet(access_token="access-abc", metadata=original)
        original["team_id"] = "mutated"
        assert token.metadata["team_id"] == "T123"

    def test_context_isolated_from_caller_mutation(self):
        original = {"user_id": "U123"}
        token = TokenSet(access_token="access-abc", context=original)
        original["user_id"] = "mutated"
        assert token.context["user_id"] == "U123"

    def test_frozen(self):
        token = TokenSet(access_token="access-abc")
        with pytest.raises(ValidationError):
            token.access_token = "other"


class TestOAuthPendingState:
    def test_with_pkce(self):
        now = time.time()
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            code_verifier="verifier-abc",
            created_at=now,
        )
        assert state.state == "random-state-token"
        assert state.code_verifier == "verifier-abc"
        assert state.created_at == now

    def test_without_pkce(self):
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
        )
        assert state.code_verifier is None

    def test_metadata_defaults_to_empty_dict(self):
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
        )
        assert state.metadata == {}

    def test_metadata_round_trips(self):
        meta = {"user_id": "U123", "tenant_id": "T456", "tool_name": "slack"}
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
            metadata=meta,
        )
        assert state.metadata == meta
        assert state.metadata["user_id"] == "U123"

    def test_metadata_isolated_from_caller_mutation(self):
        original = {"user_id": "U123"}
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
            metadata=original,
        )
        original["user_id"] = "mutated"
        assert state.metadata["user_id"] == "U123"

    def test_frozen(self):
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
        )
        with pytest.raises(ValidationError):
            state.state = "other"
