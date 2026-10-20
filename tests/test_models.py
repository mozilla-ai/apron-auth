from __future__ import annotations

import copy
import math
import pickle
import time
from pathlib import Path
from types import MappingProxyType

import pytest
from pydantic import BaseModel, SecretStr, ValidationError

from apron_auth import providers
from apron_auth.errors import ConfigurationError, IssuerValidationError
from apron_auth.models import (
    RESERVED_AUTHORIZATION_PARAMS,
    ApplicationType,
    ClientRegistration,
    FreshTokenSet,
    IdentityMaterial,
    IdentityProfile,
    OAuthPendingState,
    Provider,
    ProviderConfig,
    ScopeMetadata,
    TenancyContext,
    TokenEndpointAuthMethod,
    TokenSet,
)


class TestApplicationType:
    def test_members_are_in_alphabetical_order(self) -> None:
        names = [member.name for member in ApplicationType]
        assert names == sorted(names)

    def test_values_are_the_registered_names(self) -> None:
        assert {member.value for member in ApplicationType} == {"native", "web"}


class TestTokenEndpointAuthMethod:
    def test_members_are_in_alphabetical_order(self) -> None:
        names = [member.name for member in TokenEndpointAuthMethod]
        assert names == sorted(names)

    def test_values_are_the_registered_names(self) -> None:
        assert {member.value for member in TokenEndpointAuthMethod} == {
            "client_secret_basic",
            "client_secret_post",
            "none",
        }

    def test_a_method_this_library_cannot_perform_is_not_a_member(self) -> None:
        with pytest.raises(ValueError, match="private_key_jwt"):
            TokenEndpointAuthMethod("private_key_jwt")

    @pytest.mark.parametrize(
        ("method", "requires_secret"),
        [
            (TokenEndpointAuthMethod.CLIENT_SECRET_BASIC, True),
            (TokenEndpointAuthMethod.CLIENT_SECRET_POST, True),
            (TokenEndpointAuthMethod.NONE, False),
        ],
    )
    def test_each_member_says_whether_its_client_sends_a_secret(
        self, method: TokenEndpointAuthMethod, requires_secret: bool
    ) -> None:
        assert method.requires_secret is requires_secret


class TestClientRegistration:
    def test_a_method_this_library_cannot_perform_is_refused(self) -> None:
        """The registration's method is read off a server document, so it is validated into the type."""
        with pytest.raises(ValidationError):
            ClientRegistration(client_id="c", token_endpoint_auth_method="private_key_jwt")

    def test_a_registered_method_is_the_enum_member(self) -> None:
        registration = ClientRegistration(client_id="c", token_endpoint_auth_method="none")
        assert registration.token_endpoint_auth_method is TokenEndpointAuthMethod.NONE


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
        assert config.resource is None

    def test_max_pending_age_defaults_to_ten_minutes(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.max_pending_age_seconds == 600

    @pytest.mark.parametrize(
        "max_age", [0, -1, math.inf, math.nan], ids=["zero", "negative", "infinite", "not-a-number"]
    )
    def test_max_pending_age_rejects_a_value_that_is_not_positive_and_finite(self, max_age: float) -> None:
        with pytest.raises(ValidationError, match="max_pending_age_seconds must be a positive finite number"):
            ProviderConfig(
                client_id="test-client",
                client_secret=SecretStr("test-secret"),
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                max_pending_age_seconds=max_age,
            )

    @pytest.mark.parametrize(
        "resource",
        ["https://mcp.example.com/", "urn:example:resource"],
    )
    def test_resource_accepts_absolute_uri(self, resource: str) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            resource=resource,
        )
        assert config.resource == resource

    @pytest.mark.parametrize(
        "bad_resource",
        [
            "",
            "mcp.example.com/mcp",
            "/relative/path",
            "https://mcp.example.com/#section",
            "https://mcp.example.com/#",
        ],
    )
    def test_resource_rejects_non_absolute_or_fragmented_uri(self, bad_resource: str) -> None:
        with pytest.raises(ValidationError):
            ProviderConfig(
                client_id="test-client",
                client_secret=SecretStr("test-secret"),
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                resource=bad_resource,
            )

    def test_public_client_omits_client_secret(self) -> None:
        config = ProviderConfig(
            client_id="public-client",
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            token_endpoint_auth_method="none",
        )
        assert config.client_secret is None

    def test_basic_auth_returns_credential_for_confidential_client(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.basic_auth() == ("test-client", "test-secret")

    def test_basic_auth_returns_none_for_public_client(self) -> None:
        config = ProviderConfig(
            client_id="public-client",
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            token_endpoint_auth_method="none",
        )
        assert config.basic_auth() is None

    def test_basic_auth_keys_off_auth_method_not_secret_presence(self) -> None:
        """A public client presents no credential even with a lingering secret.

        The validator makes ``none`` + secret unconstructable, so
        ``model_construct`` bypasses it to prove the send-credentials decision
        follows the declared method, not the mere presence of a secret.
        """
        config = ProviderConfig.model_construct(
            client_id="public-client",
            client_secret=SecretStr("leaked-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            token_endpoint_auth_method="none",
        )
        assert config.basic_auth() is None

    @pytest.mark.parametrize(
        ("secret", "auth_method", "raises"),
        [
            (None, "none", False),
            (SecretStr("s"), "none", True),
            (None, "client_secret_post", True),
            (None, "client_secret_basic", True),
            (SecretStr("s"), "client_secret_post", False),
            (SecretStr("s"), "client_secret_basic", False),
        ],
    )
    def test_client_secret_presence_must_match_auth_method(
        self, secret: SecretStr | None, auth_method: str, raises: bool
    ) -> None:
        def build() -> ProviderConfig:
            return ProviderConfig(
                client_id="c",
                client_secret=secret,
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                token_endpoint_auth_method=auth_method,
            )

        if raises:
            with pytest.raises(ValidationError):
                build()
        else:
            build()

    def test_a_dump_carries_the_auth_method_as_the_member_and_as_its_name_in_json_mode(self) -> None:
        config = ProviderConfig(
            client_id="c",
            client_secret=SecretStr("s"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            token_endpoint_auth_method="client_secret_basic",
        )
        assert config.model_dump()["token_endpoint_auth_method"] is TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
        assert config.model_dump(mode="json")["token_endpoint_auth_method"] == "client_secret_basic"

    def test_an_auth_method_this_library_cannot_perform_is_refused(self) -> None:
        """A method outside the closed set would be sent to the token endpoint and rejected there."""
        with pytest.raises(ValidationError):
            ProviderConfig(
                client_id="c",
                client_secret=SecretStr("s"),
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                token_endpoint_auth_method="private_key_jwt",
            )

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

    @pytest.mark.parametrize("name", sorted(RESERVED_AUTHORIZATION_PARAMS))
    def test_extra_params_cannot_set_a_reserved_parameter(self, name: str) -> None:
        """A parameter that binds the request to the client, or replaces it, is refused when the config is built."""
        with pytest.raises(ValidationError, match=f"reserved authorization request parameters: {name}"):
            ProviderConfig(
                client_id="test-client",
                client_secret=SecretStr("test-secret"),
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                extra_params={name: "value"},
            )

    def test_extra_params_error_names_every_refused_parameter(self) -> None:
        with pytest.raises(ValidationError, match="response_type, state"):
            ProviderConfig(
                client_id="test-client",
                client_secret=SecretStr("test-secret"),
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                extra_params={"state": "fixed", "prompt": "consent", "response_type": "token"},
            )

    @pytest.mark.parametrize(
        "params",
        [{"scope": "openid email"}, {"access_type": "offline", "prompt": "consent"}],
        ids=["scope", "provider parameters"],
    )
    def test_extra_params_may_set_scope_and_provider_parameters(self, params: dict[str, str]) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            extra_params=params,
        )
        assert config.extra_params == params

    def test_reserved_parameters_are_the_ones_that_bind_or_replace_the_request(self) -> None:
        """Removing a name from the reserved set must be a deliberate change, not a silent one."""
        assert {
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "nonce",
            "redirect_uri",
            "request",
            "request_uri",
            "resource",
            "response_type",
            "state",
        } == RESERVED_AUTHORIZATION_PARAMS

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

    def test_issuer_and_require_iss_default_to_absent(self) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.issuer is None
        assert config.require_iss is False


class TestProviderConfigUnknownFields:
    @pytest.mark.parametrize("field", ["allow_identity_inference", "redirect_url"])
    def test_rejects_a_field_it_does_not_define(self, field: str) -> None:
        """A field this model does not define is refused, so a renamed or mistyped one cannot be dropped."""
        with pytest.raises(ValidationError, match=field):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                **{field: False},
            )


class TestProviderConfigKeepsTheCallersMapping:
    def test_validation_adds_no_key_to_the_mapping_it_was_given(self) -> None:
        """A caller that reuses or re-persists its mapping must not find a provider's facts in it."""
        raw = {
            "provider": "google",
            "client_id": "cid",
            "client_secret": "csec",  # pragma: allowlist secret
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
        }
        given = set(raw)

        config = ProviderConfig.model_validate(raw)

        assert config.can_assert_domain_ownership is True
        assert set(raw) == given


class TestProviderConfigTakesFactsFromAnyMapping:
    def test_a_mapping_that_is_not_a_dict_takes_the_members_facts(self) -> None:
        """A caller's stored mapping validates the same whatever mapping type holds it."""
        raw = MappingProxyType(
            {
                "provider": "google",
                "client_id": "cid",
                "client_secret": "csec",  # pragma: allowlist secret
                "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_url": "https://oauth2.googleapis.com/token",
            }
        )

        config = ProviderConfig.model_validate(raw)

        assert config.can_assert_domain_ownership is True
        assert config.disconnect_fully_revokes is True


class TestProviderConfigValidateIssuer:
    def _config(self, **overrides: object) -> ProviderConfig:
        defaults: dict[str, object] = {
            "client_id": "test-client",
            "client_secret": SecretStr("test-secret"),
            "authorize_url": "https://provider.example.com/authorize",
            "token_url": "https://provider.example.com/token",
        }
        defaults.update(overrides)
        return ProviderConfig(**defaults)

    def test_no_expected_issuer_ignores_received_iss(self) -> None:
        # A preset carries no expected issuer, so a received iss cannot be
        # validated and is not grounds for rejection.
        self._config().validate_issuer("https://anything.example.com")

    def test_matching_iss_passes(self) -> None:
        config = self._config(issuer="https://auth.example.com")
        config.validate_issuer("https://auth.example.com")

    def test_mismatched_iss_raises(self) -> None:
        config = self._config(issuer="https://auth.example.com")
        with pytest.raises(IssuerValidationError):
            config.validate_issuer("https://attacker.example.com")

    def test_missing_iss_raises_when_required(self) -> None:
        config = self._config(issuer="https://auth.example.com", require_iss=True)
        with pytest.raises(IssuerValidationError):
            config.validate_issuer(None)

    def test_missing_iss_allowed_when_not_required(self) -> None:
        config = self._config(issuer="https://auth.example.com", require_iss=False)
        config.validate_issuer(None)


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


class _Session(BaseModel):
    user: str
    tokens: FreshTokenSet


class _Sessions(BaseModel):
    tokens: list[FreshTokenSet]


class TestFreshTokenSet:
    def test_keyword_construction_builds_a_token_set(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc", metadata={"id_token": "id-jwt"})
        assert isinstance(tokens, TokenSet)
        assert tokens.access_token == "access-abc"
        assert tokens.metadata == {"id_token": "id-jwt"}

    def test_frozen(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc")
        with pytest.raises(ValidationError):
            tokens.access_token = "other"

    def test_model_validate_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="stored data"):
            FreshTokenSet.model_validate({"access_token": "access-abc"})

    def test_model_validate_json_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="stored data"):
            FreshTokenSet.model_validate_json('{"access_token": "access-abc"}')

    def test_model_validate_strings_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="stored data"):
            FreshTokenSet.model_validate_strings({"access_token": "access-abc"})

    def test_the_fields_reload_as_a_plain_token_set(self) -> None:
        fresh = FreshTokenSet(access_token="access-abc", refresh_token="refresh-xyz", metadata={"id_token": "id-jwt"})
        stored = TokenSet.model_validate(fresh.model_dump())
        assert not isinstance(stored, FreshTokenSet)
        assert stored.model_dump() == fresh.model_dump()

    def test_a_model_holding_one_cannot_reload_it_from_a_dict(self) -> None:
        with pytest.raises(ConfigurationError, match="stored data"):
            _Session.model_validate({"user": "U123", "tokens": {"access_token": "access-abc"}})

    def test_a_model_holding_one_cannot_reload_it_from_json(self) -> None:
        session = _Session(user="U123", tokens=FreshTokenSet(access_token="access-abc"))
        with pytest.raises(ConfigurationError, match="stored data"):
            _Session.model_validate_json(session.model_dump_json())

    def test_a_model_holding_a_list_of_them_cannot_reload_it(self) -> None:
        with pytest.raises(ConfigurationError, match="stored data"):
            _Sessions.model_validate({"tokens": [{"access_token": "access-abc"}]})

    def test_a_model_can_hold_an_existing_one(self) -> None:
        fresh = FreshTokenSet(access_token="access-abc")
        assert _Session(user="U123", tokens=fresh).tokens is fresh
        assert _Session.model_validate({"user": "U123", "tokens": fresh}).tokens is fresh

    def test_pickling_is_refused(self) -> None:
        fresh = FreshTokenSet(access_token="access-abc")
        with pytest.raises(ConfigurationError, match="cannot be stored"):
            pickle.dumps(fresh)

    def test_a_plain_token_set_still_pickles(self) -> None:
        stored = pickle.loads(pickle.dumps(TokenSet(access_token="access-abc")))
        assert stored == TokenSet(access_token="access-abc")

    def test_copying_keeps_the_type(self) -> None:
        fresh = FreshTokenSet(access_token="access-abc")
        assert isinstance(copy.deepcopy(fresh), FreshTokenSet)
        assert isinstance(fresh.model_copy(), FreshTokenSet)


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
        tokens = FreshTokenSet(access_token="access-abc", metadata={"id_token": "id-jwt"})
        material = IdentityMaterial.from_token_set(tokens)
        assert material.access_token == "access-abc"
        assert material.id_token == "id-jwt"

    def test_from_token_set_id_token_absent_is_none(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc", metadata={"team_id": "T123"})
        material = IdentityMaterial.from_token_set(tokens)
        assert material.id_token is None

    def test_from_token_set_non_string_id_token_is_none(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc", metadata={"id_token": 12345})
        material = IdentityMaterial.from_token_set(tokens)
        assert material.id_token is None

    def test_from_token_set_omits_refresh_token_and_context(self) -> None:
        """The narrowing must not surface the refresh token or caller
        context — those fields are structurally absent from the type."""
        tokens = FreshTokenSet(
            access_token="access-abc",
            refresh_token="refresh-xyz",
            metadata={"id_token": "id-jwt"},
            context={"user_id": "U123"},
        )
        material = IdentityMaterial.from_token_set(tokens)
        assert not hasattr(material, "refresh_token")
        assert not hasattr(material, "context")
        assert set(material.model_dump()) == {"access_token", "id_token", "scope"}

    def test_minimal_defaults_scope_to_none(self) -> None:
        material = IdentityMaterial(access_token="access-abc")
        assert material.scope is None

    def test_from_token_set_carries_granted_scope(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc", scope="accounts:read forms:read")
        material = IdentityMaterial.from_token_set(tokens)
        assert material.scope == "accounts:read forms:read"

    def test_from_token_set_absent_scope_is_none(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc")
        material = IdentityMaterial.from_token_set(tokens)
        assert material.scope is None


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


class TestProviderConfigProvider:
    def test_defaults_to_none(self) -> None:
        config = ProviderConfig(
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        assert config.provider is None

    def test_accepts_a_member_whose_facts_match(self) -> None:
        config = ProviderConfig(
            provider=Provider.LINEAR,
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://linear.app/oauth/authorize",
            token_url="https://api.linear.app/oauth/token",
            scope_separator=",",
        )
        assert config.provider is Provider.LINEAR

    def test_rejects_a_scope_separator_that_contradicts_the_member(self) -> None:
        """A value the member does not state is refused; leaving it out takes the member's."""
        with pytest.raises(ValidationError, match="scope_separator must be ',' for provider Linear, got ' '"):
            ProviderConfig(
                provider=Provider.LINEAR,
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://linear.app/oauth/authorize",
                token_url="https://api.linear.app/oauth/token",
                scope_separator=" ",
            )

    def test_rejects_a_domain_ownership_claim_that_contradicts_the_member(self) -> None:
        """A value the member does not state is refused; leaving it out takes the member's."""
        with pytest.raises(
            ValidationError, match="can_assert_domain_ownership must be False for provider Linear, got True"
        ):
            ProviderConfig(
                provider=Provider.LINEAR,
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://linear.app/oauth/authorize",
                token_url="https://api.linear.app/oauth/token",
                can_assert_domain_ownership=True,
            )

    def test_rejects_a_disconnect_fully_revokes_that_contradicts_the_member(self) -> None:
        """A value the member does not state is refused; leaving it out takes the member's."""
        with pytest.raises(
            ValidationError, match="disconnect_fully_revokes must be True for provider GitHub, got False"
        ):
            ProviderConfig(
                provider=Provider.GITHUB,
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://github.com/login/oauth/authorize",
                token_url="https://github.com/login/oauth/access_token",
                disconnect_fully_revokes=False,
            )


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

    def test_a_built_in_provider_name_becomes_its_member(self) -> None:
        identity = IdentityProfile(provider="google")
        assert identity.provider is Provider.GOOGLE

    def test_a_member_survives_a_round_trip_through_its_dump(self) -> None:
        identity = IdentityProfile(provider=Provider.GOOGLE, subject="g-1")
        rebuilt = IdentityProfile.model_validate(identity.model_dump(mode="json"))
        assert rebuilt.provider is Provider.GOOGLE

    def test_a_dump_carries_the_member_in_python_mode_and_the_name_in_json_mode(self) -> None:
        identity = IdentityProfile(provider=Provider.GOOGLE)
        assert identity.model_dump()["provider"] is Provider.GOOGLE
        assert identity.model_dump()["provider"] == "google"
        assert identity.model_dump(mode="json")["provider"] == "google"

    def test_a_generic_provider_name_stays_a_string(self) -> None:
        identity = IdentityProfile(provider="oidc:https://issuer.example")
        assert identity.provider == "oidc:https://issuer.example"
        assert type(identity.provider) is str


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

    def test_returns_a_plain_string_for_a_member(self) -> None:
        identity = IdentityProfile(provider=Provider.GITHUB, subject="12345")
        key = identity.identity_key()
        assert key == ("github", "12345")
        assert type(key[0]) is str

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


class TestProviderFactsAreDerived:
    """Test that a member states its facts once and a config does not restate them."""

    def test_a_named_provider_takes_its_facts_from_the_member(self) -> None:
        config = ProviderConfig(
            client_id="c",
            client_secret=SecretStr("s"),
            authorize_url="https://linear.app/oauth/authorize",
            token_url="https://api.linear.app/oauth/token",
            provider=Provider.LINEAR,
        )
        assert config.scope_separator == Provider.LINEAR.scope_separator
        assert config.disconnect_fully_revokes is Provider.LINEAR.disconnect_fully_revokes

    def test_a_config_with_no_provider_keeps_the_field_defaults(self) -> None:
        config = ProviderConfig(
            client_id="c",
            client_secret=SecretStr("s"),
            authorize_url="https://idp.example.com/authorize",
            token_url="https://idp.example.com/token",
        )
        assert config.scope_separator == " "
        assert config.disconnect_fully_revokes is False

    @pytest.mark.parametrize(
        ("field", "value"),
        [("scope_separator", " "), ("disconnect_fully_revokes", True)],
    )
    def test_a_value_that_contradicts_the_member_is_still_refused(self, field: str, value: object) -> None:
        with pytest.raises(ValidationError, match="Linear"):
            ProviderConfig(
                client_id="c",
                client_secret=SecretStr("s"),
                authorize_url="https://linear.app/oauth/authorize",
                token_url="https://api.linear.app/oauth/token",
                provider=Provider.LINEAR,
                **{field: value},
            )

    def test_a_value_that_agrees_with_the_member_is_accepted(self) -> None:
        config = ProviderConfig(
            client_id="c",
            client_secret=SecretStr("s"),
            authorize_url="https://linear.app/oauth/authorize",
            token_url="https://api.linear.app/oauth/token",
            provider=Provider.LINEAR,
            scope_separator=",",
        )
        assert config.scope_separator == ","

    def test_no_preset_restates_a_fact_the_member_states(self) -> None:
        """A preset names its member, so restating a fact would be a second statement of it."""
        restated = [
            f"{path.name}:{number}"
            for path in (Path(providers.__file__).parent).glob("*.py")
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
            if ("scope_separator=Provider." in line or "disconnect_fully_revokes=Provider." in line)
        ]
        assert restated == []


class TestScopeSeparator:
    """Test that a separator no scope string can be split on is refused where it is set."""

    def test_an_empty_separator_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="scope_separator must not be empty"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                scope_separator="",
            )

    def test_every_provider_member_states_a_usable_separator(self) -> None:
        assert all(member.scope_separator for member in Provider)
