from __future__ import annotations

import time

import pytest
from pydantic import SecretStr, ValidationError

from apron_auth.models import (
    IdentityProfile,
    OAuthPendingState,
    ProviderConfig,
    ScopeMetadata,
    TenancyContext,
    TokenSet,
)


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

    def test_scope_metadata_defaults_to_empty_list(self):
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.scope_metadata == []

    def test_scope_metadata_round_trips(self):
        meta = ScopeMetadata(
            scope="openid",
            label="OpenID",
            description="Authenticate the user",
            access_type="read",
            required=True,
        )
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            scope_metadata=[meta],
        )
        assert config.scope_metadata == [meta]

    def test_required_scope_families_defaults_to_empty_list(self):
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.required_scope_families == []

    def test_required_scope_families_round_trips(self):
        families = [["bot:read", "bot:write"], ["user:read"]]
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            required_scope_families=families,
        )
        assert config.required_scope_families == families


class TestScopeMetadata:
    def test_minimal_fields(self):
        meta = ScopeMetadata(
            scope="openid",
            label="OpenID",
            description="Sign you in",
            access_type="read",
        )
        assert meta.scope == "openid"
        assert meta.access_type == "read"
        assert meta.required is False

    def test_required_round_trips(self):
        meta = ScopeMetadata(
            scope="offline_access",
            label="Offline Access",
            description="Issue refresh tokens",
            access_type="read",
            required=True,
        )
        assert meta.required is True

    def test_invalid_access_type_rejected(self):
        with pytest.raises(ValidationError):
            ScopeMetadata(
                scope="openid",
                label="OpenID",
                description="Sign you in",
                access_type="bogus",  # type: ignore[arg-type]
            )

    def test_frozen(self):
        meta = ScopeMetadata(
            scope="openid",
            label="OpenID",
            description="Sign you in",
            access_type="read",
        )
        with pytest.raises(ValidationError):
            meta.scope = "other"


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


class TestTenancyContext:
    def test_defaults_to_all_none_and_empty_raw(self):
        ctx = TenancyContext()
        assert ctx.id is None
        assert ctx.name is None
        assert ctx.domain is None
        assert ctx.raw == {}

    def test_round_trips_normalized_fields(self):
        ctx = TenancyContext(id="T1", name="Acme", domain="acme.example.com", raw={"team_icon": "x"})
        assert ctx.id == "T1"
        assert ctx.name == "Acme"
        assert ctx.domain == "acme.example.com"
        assert ctx.raw == {"team_icon": "x"}

    def test_frozen(self):
        ctx = TenancyContext(id="T1")
        with pytest.raises(ValidationError):
            ctx.id = "other"

    def test_raw_isolated_from_caller_mutation(self):
        original = {"team_icon": "x"}
        ctx = TenancyContext(raw=original)
        original["team_icon"] = "mutated"
        assert ctx.raw["team_icon"] == "x"


class TestProviderConfigCanAssertDomainOwnership:
    def test_defaults_to_false(self):
        config = ProviderConfig(
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.can_assert_domain_ownership is False

    def test_can_be_set_true(self):
        config = ProviderConfig(
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            can_assert_domain_ownership=True,
        )
        assert config.can_assert_domain_ownership is True


class TestTenancyContextOwnsEmailDomain:
    def test_defaults_to_false(self):
        ctx = TenancyContext()
        assert ctx.owns_email_domain is False

    def test_can_be_set_true(self):
        ctx = TenancyContext(domain="example.com", owns_email_domain=True)
        assert ctx.owns_email_domain is True

    def test_existing_fields_unchanged(self):
        ctx = TenancyContext(
            id="t-1",
            name="Example",
            domain="example.com",
            raw={"k": "v"},
        )
        assert ctx.id == "t-1"
        assert ctx.name == "Example"
        assert ctx.domain == "example.com"
        assert ctx.raw == {"k": "v"}
        assert ctx.owns_email_domain is False


class TestIdentityProfileProvider:
    def test_defaults_to_none(self):
        identity = IdentityProfile()
        assert identity.provider is None

    def test_can_be_set(self):
        identity = IdentityProfile(provider="google", subject="g-1")
        assert identity.provider == "google"
        assert identity.subject == "g-1"


class TestIdentityProfile:
    def test_tenancies_defaults_to_empty_tuple(self):
        identity = IdentityProfile()
        assert identity.tenancies == ()

    def test_tenancies_accepts_multi_tenant_tuple(self):
        identity = IdentityProfile(
            tenancies=(
                TenancyContext(id="cloud-1", name="One"),
                TenancyContext(id="cloud-2", name="Two"),
            ),
        )
        assert len(identity.tenancies) == 2
        assert identity.tenancies[1].id == "cloud-2"

    def test_frozen(self):
        identity = IdentityProfile()
        with pytest.raises(ValidationError):
            identity.tenancies = (TenancyContext(id="T1"),)


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
