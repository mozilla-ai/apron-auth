from __future__ import annotations

import time

import pytest
from pydantic import SecretStr, ValidationError

from apron_auth.models import (
    IdentityMaterial,
    IdentityProfile,
    OAuthPendingState,
    ProviderConfig,
    ScopeMetadata,
    TenancyContext,
    TokenSet,
)


class TestProviderConfig:
    def test_minimal_config(self) -> None:
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

    def test_full_config(self) -> None:
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

    def test_frozen(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        with pytest.raises(ValidationError):
            config.client_id = "other"

    def test_secret_not_leaked_in_repr(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert "test-secret" not in repr(config)
        assert "test-secret" not in str(config)

    def test_missing_required_fields(self) -> None:
        with pytest.raises(ValidationError):
            ProviderConfig(client_id="test")

    def test_scope_metadata_defaults_to_empty_list(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.scope_metadata == []

    def test_scope_metadata_round_trips(self) -> None:
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

    def test_required_scope_families_defaults_to_empty_list(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.required_scope_families == []

    def test_required_scope_families_round_trips(self) -> None:
        families = [["bot:read", "bot:write"], ["user:read"]]
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            required_scope_families=families,
        )
        assert config.required_scope_families == families

    def test_implicit_scopes_defaults_to_empty_dict(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.implicit_scopes == {}

    def test_resolve_implicit_scopes_expands_transitively(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            implicit_scopes={"a": frozenset({"b"}), "b": frozenset({"c"})},
        )
        assert config.resolve_implicit_scopes({"a"}) == {"a", "b", "c"}

    def test_resolve_implicit_scopes_without_map_returns_input(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.resolve_implicit_scopes({"x"}) == {"x"}


class TestScopeMetadata:
    def test_minimal_fields(self) -> None:
        meta = ScopeMetadata(
            scope="openid",
            label="OpenID",
            description="Sign you in",
            access_type="read",
        )
        assert meta.scope == "openid"
        assert meta.access_type == "read"
        assert meta.required is False

    def test_required_round_trips(self) -> None:
        meta = ScopeMetadata(
            scope="offline_access",
            label="Offline Access",
            description="Issue refresh tokens",
            access_type="read",
            required=True,
        )
        assert meta.required is True

    def test_invalid_access_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopeMetadata(
                scope="openid",
                label="OpenID",
                description="Sign you in",
                access_type="bogus",  # type: ignore[arg-type]
            )

    def test_frozen(self) -> None:
        meta = ScopeMetadata(
            scope="openid",
            label="OpenID",
            description="Sign you in",
            access_type="read",
        )
        with pytest.raises(ValidationError):
            meta.scope = "other"


class TestTokenSet:
    def test_minimal_token(self) -> None:
        token = TokenSet(access_token="access-abc")
        assert token.access_token == "access-abc"
        assert token.token_type == "Bearer"
        assert token.refresh_token is None
        assert token.expires_in is None
        assert token.expires_at is None
        assert token.scope is None
        assert token.metadata == {}

    def test_full_token(self) -> None:
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

    def test_context_defaults_to_empty_dict(self) -> None:
        token = TokenSet(access_token="access-abc")
        assert token.context == {}

    def test_context_round_trips(self) -> None:
        ctx = {"user_id": "U123", "tenant_id": "T456"}
        token = TokenSet(access_token="access-abc", context=ctx)
        assert token.context == ctx
        assert token.context["user_id"] == "U123"

    def test_metadata_isolated_from_caller_mutation(self) -> None:
        original = {"team_id": "T123"}
        token = TokenSet(access_token="access-abc", metadata=original)
        original["team_id"] = "mutated"
        assert token.metadata["team_id"] == "T123"

    def test_context_isolated_from_caller_mutation(self) -> None:
        original = {"user_id": "U123"}
        token = TokenSet(access_token="access-abc", context=original)
        original["user_id"] = "mutated"
        assert token.context["user_id"] == "U123"

    def test_frozen(self) -> None:
        token = TokenSet(access_token="access-abc")
        with pytest.raises(ValidationError):
            token.access_token = "other"


class TestIdentityMaterial:
    def test_minimal_defaults_id_token_to_none(self) -> None:
        material = IdentityMaterial(access_token="access-abc")
        assert material.access_token == "access-abc"
        assert material.id_token is None

    def test_frozen(self) -> None:
        material = IdentityMaterial(access_token="access-abc")
        with pytest.raises(ValidationError):
            material.access_token = "other"

    def test_from_token_set_extracts_id_token_from_metadata(self) -> None:
        tokens = TokenSet(access_token="access-abc", metadata={"id_token": "id-jwt"})
        material = IdentityMaterial.from_token_set(tokens)
        assert material.access_token == "access-abc"
        assert material.id_token == "id-jwt"

    def test_from_token_set_id_token_absent_is_none(self) -> None:
        tokens = TokenSet(access_token="access-abc", metadata={"team_id": "T123"})
        material = IdentityMaterial.from_token_set(tokens)
        assert material.id_token is None

    def test_from_token_set_non_string_id_token_is_none(self) -> None:
        tokens = TokenSet(access_token="access-abc", metadata={"id_token": 12345})
        material = IdentityMaterial.from_token_set(tokens)
        assert material.id_token is None

    def test_from_token_set_omits_refresh_token_and_context(self) -> None:
        """The narrowing must not surface the refresh token or caller
        context — those fields are structurally absent from the type."""
        tokens = TokenSet(
            access_token="access-abc",
            refresh_token="refresh-xyz",
            metadata={"id_token": "id-jwt"},
            context={"user_id": "U123"},
        )
        material = IdentityMaterial.from_token_set(tokens)
        assert not hasattr(material, "refresh_token")
        assert not hasattr(material, "context")
        assert set(material.model_dump()) == {"access_token", "id_token"}


class TestTenancyContext:
    def test_defaults_to_all_none_and_empty_raw(self) -> None:
        ctx = TenancyContext()
        assert ctx.id is None
        assert ctx.name is None
        assert ctx.domain is None
        assert ctx.raw == {}

    def test_round_trips_normalized_fields(self) -> None:
        ctx = TenancyContext(id="T1", name="Acme", domain="acme.example.com", raw={"team_icon": "x"})
        assert ctx.id == "T1"
        assert ctx.name == "Acme"
        assert ctx.domain == "acme.example.com"
        assert ctx.raw == {"team_icon": "x"}

    def test_frozen(self) -> None:
        ctx = TenancyContext(id="T1")
        with pytest.raises(ValidationError):
            ctx.id = "other"

    def test_raw_isolated_from_caller_mutation(self) -> None:
        original = {"team_icon": "x"}
        ctx = TenancyContext(raw=original)
        original["team_icon"] = "mutated"
        assert ctx.raw["team_icon"] == "x"


class TestProviderConfigCanAssertDomainOwnership:
    def test_defaults_to_false(self) -> None:
        config = ProviderConfig(
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.can_assert_domain_ownership is False

    def test_can_be_set_true(self) -> None:
        config = ProviderConfig(
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            can_assert_domain_ownership=True,
        )
        assert config.can_assert_domain_ownership is True


class TestTenancyContextOwnsEmailDomain:
    def test_defaults_to_false(self) -> None:
        ctx = TenancyContext()
        assert ctx.owns_email_domain is False

    def test_can_be_set_true(self) -> None:
        ctx = TenancyContext(domain="example.com", owns_email_domain=True)
        assert ctx.owns_email_domain is True

    def test_existing_fields_unchanged(self) -> None:
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
    def test_defaults_to_none(self) -> None:
        identity = IdentityProfile()
        assert identity.provider is None

    def test_can_be_set(self) -> None:
        identity = IdentityProfile(provider="google", subject="g-1")
        assert identity.provider == "google"
        assert identity.subject == "g-1"


class TestIdentityProfileVerifiedEmail:
    def test_returns_email_when_verified(self) -> None:
        identity = IdentityProfile(email="user@example.com", email_verified=True)
        assert identity.verified_email() == "user@example.com"

    def test_returns_none_when_unverified(self) -> None:
        identity = IdentityProfile(email="user@example.com", email_verified=False)
        assert identity.verified_email() is None

    def test_returns_none_when_verification_unknown(self) -> None:
        identity = IdentityProfile(email="user@example.com", email_verified=None)
        assert identity.verified_email() is None

    def test_returns_none_when_email_absent(self) -> None:
        identity = IdentityProfile(email=None, email_verified=True)
        assert identity.verified_email() is None


class TestIdentityProfileIdentityKey:
    def test_returns_tuple_when_both_present(self) -> None:
        identity = IdentityProfile(provider="github", subject="12345")
        assert identity.identity_key() == ("github", "12345")

    def test_returns_none_when_provider_missing(self) -> None:
        identity = IdentityProfile(provider=None, subject="12345")
        assert identity.identity_key() is None

    def test_returns_none_when_subject_missing(self) -> None:
        identity = IdentityProfile(provider="github", subject=None)
        assert identity.identity_key() is None

    def test_returns_none_when_both_missing(self) -> None:
        identity = IdentityProfile()
        assert identity.identity_key() is None

    def test_empty_provider_treated_as_missing(self) -> None:
        identity = IdentityProfile(provider="", subject="12345")
        assert identity.identity_key() is None

    def test_empty_subject_treated_as_missing(self) -> None:
        identity = IdentityProfile(provider="github", subject="")
        assert identity.identity_key() is None


class TestIdentityProfileDomainOwningTenancies:
    def test_returns_empty_when_no_owning_tenancy(self) -> None:
        not_owning = TenancyContext(domain="example.com", owns_email_domain=False)
        identity = IdentityProfile(tenancies=(not_owning,))
        assert identity.domain_owning_tenancies() == ()

    def test_returns_empty_when_no_tenancies(self) -> None:
        identity = IdentityProfile(tenancies=())
        assert identity.domain_owning_tenancies() == ()

    def test_returns_every_owning_tenancy_in_order(self) -> None:
        first = TenancyContext(domain="a.example.com", owns_email_domain=True)
        second = TenancyContext(domain="b.example.com", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(first, second))
        assert identity.domain_owning_tenancies() == (first, second)

    def test_returns_sole_owning_tenancy(self) -> None:
        owning = TenancyContext(domain="example.com", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(owning,))
        assert identity.domain_owning_tenancies() == (owning,)

    def test_skips_non_owning_tenancies(self) -> None:
        not_owning = TenancyContext(domain="other.com", owns_email_domain=False)
        owning = TenancyContext(domain="example.com", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(not_owning, owning))
        assert identity.domain_owning_tenancies() == (owning,)

    def test_skips_owning_tenancy_with_no_domain(self) -> None:
        """An assertion that names no domain is unusable and must not qualify.

        Returning it would make this method truthy while ``owns_domain``
        answers ``False`` for every input, so a presence check would report
        domain ownership that nothing can actually gate on.
        """
        domainless = TenancyContext(id="t-1", domain=None, owns_email_domain=True)
        identity = IdentityProfile(tenancies=(domainless,))
        assert identity.domain_owning_tenancies() == ()

    def test_skips_owning_tenancy_with_blank_domain(self) -> None:
        blank = TenancyContext(id="t-1", domain="   ", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(blank,))
        assert identity.domain_owning_tenancies() == ()

    def test_agrees_with_owns_domain_on_what_qualifies(self) -> None:
        """Every returned tenancy must name a domain ``owns_domain`` accepts."""
        domainless = TenancyContext(id="t-1", domain=None, owns_email_domain=True)
        usable = TenancyContext(id="t-1", domain="example.com", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(domainless, usable))

        qualifying = identity.domain_owning_tenancies()

        assert bool(qualifying) is any(identity.owns_domain(t.domain or "") for t in identity.tenancies)
        assert all(t.domain is not None and identity.owns_domain(t.domain) for t in qualifying)


class TestIdentityProfileOwnsDomain:
    def test_blank_domain_never_matches(self) -> None:
        owning = TenancyContext(domain="example.com", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(owning,))
        assert identity.owns_domain("") is False
        assert identity.owns_domain("   ") is False

    def test_blank_domain_does_not_match_blank_tenancy_domain(self) -> None:
        owning = TenancyContext(domain="", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(owning,))
        assert identity.owns_domain("") is False

    def test_ignores_surrounding_whitespace_on_argument(self) -> None:
        owning = TenancyContext(domain="example.com", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(owning,))
        assert identity.owns_domain("  example.com  ") is True

    def test_ignores_surrounding_whitespace_on_tenancy_domain(self) -> None:
        owning = TenancyContext(domain=" example.com ", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(owning,))
        assert identity.owns_domain("example.com") is True

    def test_matches_case_insensitively(self) -> None:
        owning = TenancyContext(domain="Example.COM", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(owning,))
        assert identity.owns_domain("eXaMpLe.com") is True

    def test_matches_non_first_domain_of_multi_domain_tenant(self) -> None:
        """A tenant asserting several domains must match on any of them, not just the first.

        Entra emits one tenancy per admin-verified domain with no ordering
        guarantee, so gating on a custom domain must not depend on where the
        directory happened to list it.
        """
        onmicrosoft = TenancyContext(id="t-1", domain="contoso.onmicrosoft.com", owns_email_domain=True)
        custom = TenancyContext(id="t-1", domain="contoso.com", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(onmicrosoft, custom))
        assert identity.owns_domain("contoso.com") is True
        assert identity.owns_domain("contoso.onmicrosoft.com") is True

    def test_returns_false_when_no_tenancies(self) -> None:
        identity = IdentityProfile(tenancies=())
        assert identity.owns_domain("example.com") is False

    def test_returns_false_when_tenancy_does_not_own_domain(self) -> None:
        not_owning = TenancyContext(domain="example.com", owns_email_domain=False)
        identity = IdentityProfile(tenancies=(not_owning,))
        assert identity.owns_domain("example.com") is False

    def test_returns_false_when_tenancy_domain_is_none(self) -> None:
        owning = TenancyContext(id="t-1", domain=None, owns_email_domain=True)
        identity = IdentityProfile(tenancies=(owning,))
        assert identity.owns_domain("example.com") is False

    def test_returns_true_on_exact_match(self) -> None:
        owning = TenancyContext(domain="example.com", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(owning,))
        assert identity.owns_domain("example.com") is True

    def test_unowned_domain_does_not_match(self) -> None:
        owning = TenancyContext(domain="example.com", owns_email_domain=True)
        identity = IdentityProfile(tenancies=(owning,))
        assert identity.owns_domain("other.com") is False

    def test_does_not_match_across_subdomain_boundary(self) -> None:
        """Ownership of a parent domain must not confer ownership of a subdomain, or vice versa."""
        parent = TenancyContext(domain="example.com", owns_email_domain=True)
        assert IdentityProfile(tenancies=(parent,)).owns_domain("corp.example.com") is False

        child = TenancyContext(domain="corp.example.com", owns_email_domain=True)
        assert IdentityProfile(tenancies=(child,)).owns_domain("example.com") is False


class TestIdentityProfile:
    def test_tenancies_defaults_to_empty_tuple(self) -> None:
        identity = IdentityProfile()
        assert identity.tenancies == ()

    def test_tenancies_accepts_multi_tenant_tuple(self) -> None:
        identity = IdentityProfile(
            tenancies=(
                TenancyContext(id="cloud-1", name="One"),
                TenancyContext(id="cloud-2", name="Two"),
            ),
        )
        assert len(identity.tenancies) == 2
        assert identity.tenancies[1].id == "cloud-2"

    def test_frozen(self) -> None:
        identity = IdentityProfile()
        with pytest.raises(ValidationError):
            identity.tenancies = (TenancyContext(id="T1"),)


class TestOAuthPendingState:
    def test_with_pkce(self) -> None:
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

    def test_without_pkce(self) -> None:
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
        )
        assert state.code_verifier is None

    def test_metadata_defaults_to_empty_dict(self) -> None:
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
        )
        assert state.metadata == {}

    def test_metadata_round_trips(self) -> None:
        meta = {"user_id": "U123", "tenant_id": "T456", "tool_name": "slack"}
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
            metadata=meta,
        )
        assert state.metadata == meta
        assert state.metadata["user_id"] == "U123"

    def test_metadata_isolated_from_caller_mutation(self) -> None:
        original = {"user_id": "U123"}
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
            metadata=original,
        )
        original["user_id"] = "mutated"
        assert state.metadata["user_id"] == "U123"

    def test_frozen(self) -> None:
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
        )
        with pytest.raises(ValidationError):
            state.state = "other"
