from __future__ import annotations

import copy
import json
import logging
import math
import pickle
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from pydantic import BaseModel, SecretStr

from apron_auth import models, providers
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
    ServerMetadata,
    TenancyContext,
    TokenEndpointAuthMethod,
    TokenSet,
    UrlField,
    UrlTransport,
)

# Every model the library offers, so a new one cannot be added without the refusal rules below.
MODELS = sorted(
    (
        value
        for value in vars(models).values()
        if isinstance(value, type)
        and issubclass(value, BaseModel)
        and value.__module__ == models.__name__
        and not value.__name__.startswith("_")
    ),
    key=lambda model: model.__name__,
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
        with pytest.raises(ConfigurationError):
            ClientRegistration(client_id="c", token_endpoint_auth_method="private_key_jwt")

    def test_a_registered_method_is_the_enum_member(self) -> None:
        registration = ClientRegistration(client_id="c", token_endpoint_auth_method="none")
        assert registration.token_endpoint_auth_method is TokenEndpointAuthMethod.NONE

    def test_an_unknown_field_is_refused(self) -> None:
        """A caller persists a registration, and a misspelled secret would load it as a public client."""
        stored = {"client_id": "c", "clientSecret": "s", "token_endpoint_auth_method": "client_secret_post"}
        with pytest.raises(ConfigurationError, match="clientSecret"):
            ClientRegistration.model_validate(stored)

    def test_a_refused_unknown_field_does_not_repeat_its_value(self) -> None:
        stored = {"client_id": "c", "clientSecret": "shared-secret"}
        with pytest.raises(ConfigurationError) as refusal:
            ClientRegistration.model_validate(stored)

        assert "shared-secret" not in str(refusal.value)


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
        with pytest.raises(ConfigurationError, match="max_pending_age_seconds must be a positive finite number"):
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
        with pytest.raises(ConfigurationError):
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
            with pytest.raises(ConfigurationError):
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
        with pytest.raises(ConfigurationError):
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
        with pytest.raises(ConfigurationError, match=f"reserved authorization request parameters: {name}"):
            ProviderConfig(
                client_id="test-client",
                client_secret=SecretStr("test-secret"),
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                extra_params={name: "value"},
            )

    def test_extra_params_error_names_every_refused_parameter(self) -> None:
        with pytest.raises(ConfigurationError, match="response_type, state"):
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

    @pytest.mark.parametrize("name", sorted(RESERVED_AUTHORIZATION_PARAMS))
    def test_the_authorize_url_query_cannot_set_a_reserved_parameter(self, name: str) -> None:
        """The request drops such a parameter, so a config that sets one never sends what it states."""
        with pytest.raises(ConfigurationError, match=f"reserved authorization request parameters: {name}"):
            ProviderConfig(
                client_id="test-client",
                client_secret=SecretStr("test-secret"),
                authorize_url=f"https://provider.example.com/authorize?{name}=value",
                token_url="https://provider.example.com/token",
            )

    @pytest.mark.parametrize("query", ["state=", "state"], ids=["an empty value", "no value at all"])
    def test_the_authorize_url_query_cannot_set_a_reserved_parameter_without_a_value(self, query: str) -> None:
        """A parameter stated with no value is still stated, and the request drops it just the same."""
        with pytest.raises(ConfigurationError, match="reserved authorization request parameters: state"):
            ProviderConfig(
                client_id="test-client",
                client_secret=SecretStr("test-secret"),
                authorize_url=f"https://provider.example.com/authorize?{query}",
                token_url="https://provider.example.com/token",
            )

    def test_the_authorize_url_query_error_names_every_refused_parameter(self) -> None:
        with pytest.raises(ConfigurationError, match="response_type, state"):
            ProviderConfig(
                client_id="test-client",
                client_secret=SecretStr("test-secret"),
                authorize_url="https://provider.example.com/authorize?state=fixed&prompt=consent&response_type=token",
                token_url="https://provider.example.com/token",
            )

    def test_the_authorize_url_query_names_its_own_field_in_the_refusal(self) -> None:
        """Two sources set these parameters, so the message says which one was refused."""
        with pytest.raises(ConfigurationError, match="authorize_url"):
            ProviderConfig(
                client_id="test-client",
                client_secret=SecretStr("test-secret"),
                authorize_url="https://provider.example.com/authorize?state=fixed",
                token_url="https://provider.example.com/token",
            )

    @pytest.mark.parametrize(
        "query",
        ["scope=openid+email", "access_type=offline&prompt=consent", "ui_locales=en&ui_locales=fr"],
        ids=["scope", "provider parameters", "a repeated parameter"],
    )
    def test_the_authorize_url_query_may_set_scope_and_provider_parameters(self, query: str) -> None:
        config = ProviderConfig(
            client_id="test-client",
            client_secret=SecretStr("test-secret"),
            authorize_url=f"https://provider.example.com/authorize?{query}",
            token_url="https://provider.example.com/token",
        )
        assert config.authorize_url.endswith(query)

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
        with pytest.raises(ConfigurationError):
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
        with pytest.raises(ConfigurationError):
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
        with pytest.raises(ConfigurationError, match=field):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                **{field: False},
            )


class TestUnknownFieldRefusals:
    def test_the_models_a_caller_states_are_the_ones_that_refuse_an_unknown_field(self) -> None:
        """A model a caller writes or reloads refuses an unknown field, so a mistyped one cannot be dropped.

        The rest are built from a provider's response by this library, and every field they drop
        fails closed, so a refusal there would reject data rather than protect anything.
        """
        refusing = {model.__name__ for model in MODELS if model.model_config.get("extra") == "forbid"}

        assert refusing == {
            "ClientRegistration",
            "FreshTokenSet",
            "OAuthPendingState",
            "ProviderConfig",
            "ServerMetadata",
            "TokenSet",
            "UserToken",
        }


class TestUrlFields:
    def test_members_are_in_alphabetical_order(self) -> None:
        names = [field.value for field in UrlField]
        assert names == sorted(names)

    @pytest.mark.parametrize(
        "model",
        [model for model in MODELS if {field.value for field in UrlField} & set(model.model_fields)],
        ids=lambda model: model.__name__,
    )
    def test_every_model_holding_a_named_field_refuses_a_credential_in_it(self, model: type[BaseModel]) -> None:
        """Naming a field here gives it no rule. The model holding it has to attach the rule as well."""
        attached = {holder.func for holder in model.__pydantic_decorators__.model_validators.values()}

        assert models._refuse_a_url_carrying_a_credential in attached

    def test_the_models_declaring_endpoints_are_the_ones_stating_the_rule(self) -> None:
        """A pending state records a request that was made, so it declares no endpoint and states no rule."""
        declaring = {model.__name__ for model in MODELS if models._PLAIN_HTTP_WAIVER in model.model_fields}

        assert declaring == {"ProviderConfig", "ServerMetadata"}

    @pytest.mark.parametrize("model", MODELS, ids=lambda model: model.__name__)
    def test_a_model_recording_a_waiver_states_the_rule_the_waiver_waives(self, model: type[BaseModel]) -> None:
        """A waiver with no rule to waive would record an exception that nothing ever applied."""
        attached = {holder.func for holder in model.__pydantic_decorators__.model_validators.values()}

        assert (models._PLAIN_HTTP_WAIVER in model.model_fields) == (models._refuse_a_url_without_tls in attached)

    @pytest.mark.parametrize("model", MODELS, ids=lambda model: model.__name__)
    def test_the_scrubbing_rule_is_the_last_one_each_model_declares(self, model: type[BaseModel]) -> None:
        """It has to wrap the others, or a refusal from one of them escapes carrying the raw value."""
        declared = list(model.__pydantic_decorators__.model_validators.values())
        last = declared[-1].func

        assert getattr(last, "__func__", last) is models._refuse_without_repeating_the_value

    def test_a_scrubbed_refusal_is_not_the_class_the_framework_re_wraps(self) -> None:
        """A ValueError raised inside a validator is caught and re-wrapped with the value it was given."""
        assert not issubclass(ConfigurationError, ValueError)

    def test_every_url_field_of_every_model_is_named(self) -> None:
        """A field whose name reads as a URL and is named nowhere here has no rule to refuse a credential."""
        # A provider's profile image is the one URL this library neither requests nor sends.
        uncovered = {"avatar_url"}
        held = {
            field
            for model in MODELS
            for field in model.model_fields
            if field.endswith(("_uri", "_url")) or field in {"issuer", "resource"}
        }

        assert held - uncovered == {field.value for field in UrlField}


class TestUrlFieldTransport:
    def test_each_field_states_what_its_scheme_must_say(self) -> None:
        """A field added without stating this would be refused or waived by accident."""
        assert {field.value: field.transport for field in UrlField} == {
            "authorize_url": UrlTransport.TLS_REQUIRED,
            "issuer": UrlTransport.TLS_REQUIRED,
            "jwks_url": UrlTransport.TLS_REQUIRED,
            "redirect_uri": UrlTransport.TLS_REQUIRED,
            "registration_url": UrlTransport.TLS_REQUIRED,
            "resource": UrlTransport.UNCHECKED,
            "revocation_url": UrlTransport.TLS_REQUIRED,
            "token_url": UrlTransport.TLS_REQUIRED,
            "userinfo_url": UrlTransport.TLS_REQUIRED,
        }

    def test_members_are_in_alphabetical_order(self) -> None:
        names = [member.name for member in UrlTransport]
        assert names == sorted(names)


class TestUnsafeAllowPlainHttp:
    """The one way to accept plain http where it would cross a network."""

    def _values(self, **overrides: str) -> dict[str, str]:
        values = {
            "client_id": "cid",
            "client_secret": "csec",  # pragma: allowlist secret
            "authorize_url": "https://provider.example.com/authorize",
            "token_url": "https://provider.example.com/token",
        }
        values.update(overrides)
        return values

    def test_it_accepts_plain_http_for_the_field_it_names(self) -> None:
        config = ProviderConfig.unsafe.allow_plain_http(
            "token_url", **self._values(token_url="http://keycloak:8080/token")
        )

        assert config.token_url == "http://keycloak:8080/token"
        assert config.allow_insecure_http_for == frozenset({UrlField.TOKEN_URL})

    def test_it_waives_no_field_it_does_not_name(self) -> None:
        """A waiver that spread would turn one accepted endpoint into a blanket exception."""
        with pytest.raises(ConfigurationError, match="authorize_url must use https"):
            ProviderConfig.unsafe.allow_plain_http(
                "token_url",
                **self._values(authorize_url="http://keycloak:8080/authorize", token_url="http://keycloak:8080/token"),
            )

    def test_it_refuses_a_name_that_is_no_url_field(self) -> None:
        with pytest.raises(ConfigurationError, match="allow_insecure_http_for"):
            ProviderConfig.unsafe.allow_plain_http("toekn_url", **self._values(token_url="http://keycloak:8080/token"))

    def test_it_says_so_in_the_log(self, caplog: pytest.LogCaptureFixture) -> None:
        """An exception nobody can see is an exception nobody reviews."""
        with caplog.at_level(logging.WARNING, logger="apron_auth.models"):
            ProviderConfig.unsafe.allow_plain_http("token_url", **self._values(token_url="http://keycloak:8080/token"))

        assert "plain http accepted for ['token_url']" in caplog.text

    def test_a_refused_build_logs_no_waiver(self, caplog: pytest.LogCaptureFixture) -> None:
        """A line in the log names a waiver in force, so a build that was refused writes none."""
        with (
            caplog.at_level(logging.WARNING, logger="apron_auth.models"),
            pytest.raises(ConfigurationError, match="authorize_url must use https"),
        ):
            ProviderConfig.unsafe.allow_plain_http(
                "token_url",
                **self._values(
                    authorize_url="http://keycloak:8080/authorize",
                    token_url="http://keycloak:8080/token",
                ),
            )

        assert "plain http accepted" not in caplog.text

    def test_the_metadata_model_states_a_waiver_the_same_way(self) -> None:
        metadata = ServerMetadata.unsafe.allow_plain_http(
            "token_url",
            authorize_url="https://auth.example.com/authorize",
            token_url="http://keycloak:8080/token",
        )

        assert metadata.allow_insecure_http_for == frozenset({UrlField.TOKEN_URL})

    def test_a_waiver_stated_as_a_keyword_is_refused(self) -> None:
        """A waiver that any caller could set would be no statement in code at all."""
        with pytest.raises(ConfigurationError, match="stated through unsafe.allow_plain_http"):
            ProviderConfig(
                **self._values(token_url="http://keycloak:8080/token"),
                allow_insecure_http_for={"token_url"},
            )

    def test_a_waiver_read_back_out_of_storage_is_refused(self) -> None:
        """A waiver is a statement about one machine, and storage carries it to another."""
        config = ProviderConfig.unsafe.allow_plain_http(
            "token_url", **self._values(token_url="http://keycloak:8080/token")
        )

        with pytest.raises(ConfigurationError, match="stated through unsafe.allow_plain_http"):
            ProviderConfig.model_validate_json(config.model_dump_json())

    @pytest.mark.parametrize(
        ("model", "data"),
        [
            pytest.param(
                ProviderConfig,
                {
                    "client_id": "cid",
                    "client_secret": "csec",  # pragma: allowlist secret
                    "authorize_url": "https://provider.example.com/authorize",
                    "token_url": "http://keycloak:8080/token",
                    "allow_insecure_http_for": ["token_url"],
                },
                id="a config",
            ),
            pytest.param(
                ServerMetadata,
                {
                    "authorize_url": "https://auth.example.com/authorize",
                    "token_url": "http://keycloak:8080/token",
                    "allow_insecure_http_for": ["token_url"],
                },
                id="metadata",
            ),
        ],
    )
    @pytest.mark.parametrize(
        "build",
        [
            pytest.param(lambda model, data, context: model.model_validate(data, context=context), id="a mapping"),
            pytest.param(
                lambda model, data, context: model.model_validate_json(json.dumps(data), context=context), id="json"
            ),
            pytest.param(
                lambda model, data, context: model.model_validate(
                    SimpleNamespace(**data), context=context, from_attributes=True
                ),
                id="from attributes",
            ),
        ],
    )
    def test_a_waiver_cannot_be_stated_through_a_validation_context(
        self, model: type[BaseModel], data: dict[str, object], build: Callable[..., object]
    ) -> None:
        """Validation context is a public argument, so a waiver that trusted it could arrive as data."""
        forged = (
            {"allow_insecure_http_for": True},
            {"allow_insecure_http_for": 1},
            {"allow_insecure_http_for": copy.deepcopy(models._WAIVER_SENTINEL)},
            "anything",
            None,
        )

        for context in forged:
            with pytest.raises(ConfigurationError, match="stated through unsafe.allow_plain_http"):
                build(model, data, context)

    @pytest.mark.parametrize(
        "field",
        ["resource", "jwks_url"],
        ids=["a field that states no transport", "a field the config does not hold"],
    )
    def test_it_refuses_a_waiver_that_waives_nothing(self, field: str) -> None:
        """A recorded waiver names what it covers, so one that covers nothing would misstate the config."""
        with pytest.raises(ConfigurationError, match=f"{field} needs no waiver"):
            ProviderConfig.unsafe.allow_plain_http(field, **self._values())

    def test_the_config_namespace_builds_a_config(self) -> None:
        """A nested namespace cannot see which model it was reached through, so each states its own."""
        built = ProviderConfig.unsafe.allow_plain_http(
            "token_url", **self._values(token_url="http://keycloak:8080/token")
        )

        assert type(built) is ProviderConfig

    def test_the_metadata_namespace_builds_metadata(self) -> None:
        built = ServerMetadata.unsafe.allow_plain_http(
            "token_url",
            authorize_url="https://auth.example.com/authorize",
            token_url="http://keycloak:8080/token",
        )

        assert type(built) is ServerMetadata

    @pytest.mark.parametrize(
        "token_url",
        ["ws://keycloak:8080/token", "javascript:alert(1)", "//keycloak:8080/token", "http:///token"],
        ids=["websocket", "javascript", "scheme relative", "no host"],
    )
    def test_it_accepts_plain_http_and_nothing_else(self, token_url: str) -> None:
        """A waiver names plain http to a host, so a field it covers refuses everything else."""
        with pytest.raises(ConfigurationError, match="token_url must use https"):
            ProviderConfig.unsafe.allow_plain_http("token_url", **self._values(token_url=token_url))

    def test_a_waived_field_still_refuses_an_empty_value(self) -> None:
        """An empty value names no host to reach, whatever a waiver says."""
        with pytest.raises(ConfigurationError, match="token_url must not be empty"):
            ProviderConfig.unsafe.allow_plain_http("token_url", **self._values(token_url=""))

    def test_a_context_that_only_compares_equal_is_refused(self) -> None:
        """The token is compared by identity, so a value that claims equality states nothing."""

        class _EqualToAnything:
            def __eq__(self, other: object) -> bool:
                return True

            def __hash__(self) -> int:
                return 0

        with pytest.raises(ConfigurationError, match="stated through unsafe.allow_plain_http"):
            ProviderConfig.model_validate(
                {**self._values(token_url="http://keycloak:8080/token"), "allow_insecure_http_for": ["token_url"]},
                context={"allow_insecure_http_for": _EqualToAnything()},
            )

    def test_a_waiver_that_came_from_data_is_named_as_such_before_what_it_waives(self) -> None:
        """Where a waiver came from is settled before what it covers, so forging it is what gets named."""
        with pytest.raises(ConfigurationError, match="stated through unsafe.allow_plain_http"):
            ProviderConfig.model_validate({**self._values(), "allow_insecure_http_for": ["resource"]})

    def test_a_waived_config_cannot_be_validated_as_a_field_of_another_model(self) -> None:
        """Validating a model as a field states no context, so a waiver cannot be told from data there."""

        class Settings(BaseModel):
            oauth: ProviderConfig

        config = ProviderConfig.unsafe.allow_plain_http(
            "token_url", **self._values(token_url="http://keycloak:8080/token")
        )

        with pytest.raises(ConfigurationError, match="stated through unsafe.allow_plain_http"):
            Settings(oauth=config)

    @pytest.mark.parametrize("model", [ProviderConfig, ServerMetadata], ids=["a config", "metadata"])
    def test_the_schema_states_that_a_waiver_is_not_settable(self, model: type[BaseModel]) -> None:
        """A consumer generating a validator from the schema would otherwise send a document we refuse."""
        field = model.model_json_schema()["properties"]["allow_insecure_http_for"]

        assert field["readOnly"] is True

    def test_a_waived_model_cannot_be_pickled(self) -> None:
        """Pickling is storage, and a waiver states an exception for the machine that stated it."""
        config = ProviderConfig.unsafe.allow_plain_http(
            "token_url", **self._values(token_url="http://keycloak:8080/token")
        )

        with pytest.raises(ConfigurationError, match="cannot be stored"):
            pickle.dumps(config)

    def test_a_config_with_no_waiver_round_trips(self) -> None:
        """Only a waiver blocks a reload, so an ordinary stored config still loads."""
        config = ProviderConfig(**self._values())

        reloaded = ProviderConfig.model_validate_json(config.model_dump_json())

        assert reloaded.token_url == config.token_url
        assert reloaded.allow_insecure_http_for == frozenset()


class TestUrlSchemes:
    @pytest.mark.parametrize("field", ["authorize_url", "issuer", "revocation_url", "token_url"])
    def test_a_config_endpoint_must_use_https(self, field: str) -> None:
        """This library sends the client's secret and the user's tokens to these, so TLS is not optional."""
        endpoints = {
            "authorize_url": "https://provider.example.com/authorize",
            "token_url": "https://provider.example.com/token",
        }
        endpoints[field] = f"http://provider.example.com/{field}"

        with pytest.raises(ConfigurationError, match=f"{field} must use https"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                **endpoints,
            )

    @pytest.mark.parametrize(
        "field", ["authorize_url", "issuer", "jwks_url", "registration_url", "revocation_url", "userinfo_url"]
    )
    def test_a_discovered_endpoint_must_use_https(self, field: str) -> None:
        """A document states these, and a document is not a reason to send a token in the clear."""
        urls = {
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
        }
        urls[field] = f"http://auth.example.com/{field}"

        with pytest.raises(ConfigurationError, match=f"{field} must use https"):
            ServerMetadata(**urls)

    def test_a_redirect_uri_off_loopback_must_use_https(self) -> None:
        """A code arrives at the redirect URI, so a public network must not carry it in the clear."""
        with pytest.raises(ConfigurationError, match="redirect_uri must use https"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                redirect_uri="http://app.example.com/callback",
            )

    @pytest.mark.parametrize(
        "host",
        ["localhost", "127.0.0.1", "127.9.9.9", "[::1]", "localhost."],
        ids=["by name", "dotted quad", "elsewhere in the range", "ipv6", "trailing dot"],
    )
    def test_a_loopback_redirect_uri_may_use_plain_http(self, host: str) -> None:
        """A native client listens on the loopback interface, where no network carries the code."""
        config = ProviderConfig(
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            redirect_uri=f"http://{host}:8080/callback",
        )

        assert config.redirect_uri == f"http://{host}:8080/callback"

    @pytest.mark.parametrize(
        "token_url",
        [
            "ws://provider.example.com/token",
            "ftp://provider.example.com/token",
            "file:///etc/passwd",
            "provider.example.com/token",
            "//provider.example.com/token",
            "https:///token",
        ],
        ids=["websocket", "ftp", "file", "no scheme", "scheme relative", "no host"],
    )
    def test_only_https_states_the_protection_an_endpoint_needs(self, token_url: str) -> None:
        """A rule that only refused http would accept a scheme that carries the secret in the clear."""
        with pytest.raises(ConfigurationError, match="token_url must use https"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url=token_url,
            )

    @pytest.mark.parametrize(
        "field",
        ["authorize_url", "issuer", "redirect_uri", "revocation_url", "token_url"],
    )
    def test_an_empty_endpoint_is_refused(self, field: str) -> None:
        """An empty value names no endpoint, so a config holding one is a misconfiguration, not a default."""
        values = {
            "client_id": "cid",
            "client_secret": SecretStr("csec"),  # pragma: allowlist secret
            "authorize_url": "https://provider.example.com/authorize",
            "token_url": "https://provider.example.com/token",
            field: "",
        }

        with pytest.raises(ConfigurationError, match=f"{field} must not be empty"):
            ProviderConfig(**values)

    @pytest.mark.parametrize(
        "token_url",
        [
            pytest.param("https://provider.example.com:not-a-port/token", id="a port that is not a number"),
            pytest.param("https://provider.example.com:99999/token", id="a port out of range"),
        ],
    )
    def test_an_endpoint_whose_port_cannot_be_read_is_refused(self, token_url: str) -> None:
        """An HTTP client refuses such a URL, so accepting it would move the refusal to the request."""
        with pytest.raises(ConfigurationError, match="token_url is malformed"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url=token_url,
            )

    def test_metadata_accepts_a_loopback_endpoint_over_plain_http(self) -> None:
        """A request to a loopback host reaches no network, so it needs no waiver on either model."""
        built = ServerMetadata(
            authorize_url="http://localhost:8080/authorize",
            token_url="http://127.0.0.1:8080/token",
        )

        assert built.allow_insecure_http_for == frozenset()

    @pytest.mark.parametrize(
        "host",
        ["2130706433", "0x7f000001", "127.1", "sub.localhost"],
        ids=["decimal", "hexadecimal", "short form", "a name under localhost"],
    )
    def test_a_host_resolvers_disagree_about_is_not_read_as_loopback(self, host: str) -> None:
        """Only the reserved name and a canonical address are read as loopback, because the rest differ."""
        with pytest.raises(ConfigurationError, match="token_url must use https"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url=f"http://{host}:8080/token",
            )

    def test_an_octal_loopback_form_is_refused_as_unreadable(self) -> None:
        """An HTTP client refuses this form outright, so it never reaches the loopback question."""
        with pytest.raises(ConfigurationError, match="token_url is malformed"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url="http://0177.0.0.1:8080/token",
            )

    def test_a_private_use_scheme_redirect_uri_is_refused(self) -> None:
        """A native client's own scheme states no transport this library can check, so it is refused."""
        with pytest.raises(ConfigurationError, match="redirect_uri must use https"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                redirect_uri="com.example.app:/callback",
            )

    def test_a_pending_state_states_no_transport_of_its_own(self) -> None:
        """A pending state records a request that was made, rather than declaring an endpoint."""
        pending = OAuthPendingState(
            state="random-state-token",
            redirect_uri="http://app.example.com/callback",
            created_at=1.0,
        )

        assert pending.redirect_uri == "http://app.example.com/callback"

    def test_a_resource_states_no_transport(self) -> None:
        """The resource identifies an API rather than naming an endpoint this library requests."""
        config = ProviderConfig(
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            resource="http://api.example.com/",
        )

        assert config.resource == "http://api.example.com/"


class TestProviderConfigUrlCredentials:
    @pytest.mark.parametrize("field", [f.value for f in UrlField if f.value in ProviderConfig.model_fields])
    @pytest.mark.parametrize(
        "authority",
        [
            pytest.param("operator:sesame@", id="a user and a password"),  # pragma: allowlist secret
            pytest.param("operator@", id="a user alone"),
            pytest.param("@", id="an empty user"),
        ],
    )
    def test_rejects_a_credential_in_an_endpoint_authority(self, field: str, authority: str) -> None:
        """A delimiter in the authority is refused whether or not it carries a value, so the rule stays one rule."""
        endpoints = {
            "authorize_url": "https://provider.example.com/authorize",
            "token_url": "https://provider.example.com/token",
        }
        endpoints[field] = f"https://{authority}provider.example.com/endpoint"

        with pytest.raises(ConfigurationError, match="must not carry userinfo"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                **endpoints,
            )

    def test_a_url_the_parser_cannot_read_is_refused(self) -> None:
        """A URL the parser cannot read states nothing about its authority, so no field may hold one."""
        with pytest.raises(ConfigurationError, match="authorize_url is malformed"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://[::1/authorize",
                token_url="https://provider.example.com/token",
            )

    def test_the_refusal_message_names_only_the_field(self) -> None:
        """The refusal names the field that failed and nothing else, so a log of it carries no value."""
        with pytest.raises(ConfigurationError) as exc_info:
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url="https://operator:sesame@provider.example.com/token",  # pragma: allowlist secret
            )

        assert str(exc_info.value) == "token_url must not carry userinfo"


class _Settings(BaseModel):
    """A caller's model holding a config, so a nested refusal can be observed."""

    config: ProviderConfig


class TestARefusalRepeatsNoValue:
    """A framework refusal carries the raw input and a path of its own, and neither is this library's."""

    def test_a_config_refusal_repeats_no_secret_and_no_url(self) -> None:
        secret = "THE_" + "REAL_SECRET"  # pragma: allowlist secret
        payload = {
            "client_id": "cid",
            "client_secret": secret,
            "authorize_url": "https://provider.example.com/authorize",
            "token_url": "https://operator:" + "sesame@provider.example.com/token",
        }

        with pytest.raises(ConfigurationError, match="token_url must not carry userinfo") as exc_info:
            ProviderConfig(**payload)

        rendered = "".join(traceback.format_exception(exc_info.value))
        assert secret not in rendered
        assert "operator" not in rendered
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    def test_a_token_set_refusal_repeats_no_token(self) -> None:
        token = "THE_" + "REAL_TOKEN"  # pragma: allowlist secret

        with pytest.raises(ConfigurationError) as exc_info:
            TokenSet.model_validate({"access_token": token, "expires_in": "not-a-number"})

        rendered = "".join(traceback.format_exception(exc_info.value))
        assert token not in rendered
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    @pytest.mark.parametrize(
        "build",
        [
            pytest.param(lambda data: ProviderConfig(**data), id="keyword construction"),
            pytest.param(ProviderConfig.model_validate, id="model_validate"),
            pytest.param(lambda data: ProviderConfig.model_validate_json(json.dumps(data)), id="from json"),
            pytest.param(ProviderConfig.model_validate_strings, id="from strings"),
            pytest.param(lambda data: _Settings(config=data), id="nested as a field"),
        ],
    )
    def test_every_entry_point_scrubs_the_refusal(self, build: Callable[[dict[str, str]], object]) -> None:
        """An entry point that refuses without scrubbing would leak while the others look uniform."""
        secret = "THE_" + "REAL_SECRET"  # pragma: allowlist secret
        data = {
            "client_id": "cid",
            "client_secret": secret,
            "authorize_url": "https://provider.example.com/authorize",
            "token_url": "https://operator:" + "sesame@provider.example.com/token",
        }

        with pytest.raises(ConfigurationError) as exc_info:
            build(data)

        rendered = "".join(traceback.format_exception(exc_info.value))
        assert secret not in rendered
        assert "operator" not in rendered

    def test_a_refusal_keeps_a_mapping_key_that_reads_like_the_marker(self) -> None:
        """A key a caller chose is the caller's, and dropping it names a path the model does not have."""
        with pytest.raises(ConfigurationError) as exc_info:
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                implicit_scopes={"[key]": {7}},  # ty: ignore[invalid-argument-type]
            )

        assert "implicit_scopes.[key].0" in str(exc_info.value)

    def test_a_refusal_names_no_marker_the_framework_uses_for_a_mapping_key(self) -> None:
        """A path the framework builds for a mapping key names no field of this model."""
        with pytest.raises(ConfigurationError) as exc_info:
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                extra_params={7: "x"},
            )

        assert "[key]" not in str(exc_info.value)

    def test_a_pending_state_refusal_repeats_no_secret(self) -> None:
        verifier = "THE_" + "REAL_VERIFIER"

        with pytest.raises(ConfigurationError) as exc_info:
            OAuthPendingState.model_validate({"state": "s", "code_verifier": verifier, "created_at": "not-a-number"})

        rendered = "".join(traceback.format_exception(exc_info.value))
        assert verifier not in rendered
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    @pytest.mark.parametrize("model", MODELS, ids=lambda model: model.__name__)
    def test_every_model_scrubs_a_refusal(self, model: type[BaseModel]) -> None:
        """An unscrubbed model repeats every value it was given, and some of them hold a credential."""
        with pytest.raises(ConfigurationError):
            model.model_validate(object())

    @pytest.mark.parametrize("model", MODELS, ids=lambda model: model.__name__)
    def test_every_model_refuses_a_malformed_document(self, model: type[BaseModel]) -> None:
        """A document that is not valid JSON is refused before any field is read, and carries all of it."""
        with pytest.raises(ConfigurationError):
            model.model_validate_json("{")

    def test_a_malformed_document_repeats_no_value(self) -> None:
        token = "THE_" + "REAL_TOKEN"  # pragma: allowlist secret
        document = json.dumps({"access_token": token, "token_type": "Bearer"})

        with pytest.raises(ConfigurationError) as exc_info:
            TokenSet.model_validate_json(document[:-3])

        rendered = "".join(traceback.format_exception(exc_info.value))
        assert token not in rendered
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    @pytest.mark.parametrize("model", MODELS, ids=lambda model: model.__name__)
    def test_every_model_scrubs_after_its_own_rules(self, model: type[BaseModel]) -> None:
        """An after or wrap rule of a model's own escapes unscrubbed unless the scrub is attached last."""
        last = list(model.__pydantic_decorators__.model_validators.values())[-1].func

        assert getattr(last, "__func__", last) is models._refuse_without_repeating_the_value

    @pytest.mark.parametrize("model", MODELS, ids=lambda model: model.__name__)
    def test_every_model_scrubs_the_entry_points_it_owns(self, model: type[BaseModel]) -> None:
        """A model stating the framework's base refuses a change, a document and strings with its error."""
        assert issubclass(model, models._RefusesWithoutRepeating)

    @pytest.mark.parametrize("model", MODELS, ids=lambda model: model.__name__)
    def test_every_model_keeps_the_shared_rule_for_a_change(self, model: type[BaseModel]) -> None:
        """Stating the base is not keeping its rule, and this module overrides these entry points."""
        assert model.__setattr__ is models._RefusesWithoutRepeating.__setattr__

    @pytest.mark.parametrize("model", MODELS, ids=lambda model: model.__name__)
    def test_every_model_refuses_a_malformed_mapping_of_strings(self, model: type[BaseModel]) -> None:
        """A value that is not a mapping is refused before any field of it is read, and carries all of it."""
        with pytest.raises(ConfigurationError):
            model.model_validate_strings(b"{")

    def test_identity_material_repeats_no_token_it_was_given(self) -> None:
        token = "THE_" + "REAL_ID_TOKEN"  # pragma: allowlist secret

        with pytest.raises(ConfigurationError) as exc_info:
            IdentityMaterial.model_validate({"id_token": token})

        rendered = "".join(traceback.format_exception(exc_info.value))
        assert token not in rendered
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    @pytest.mark.parametrize(
        ("model", "payload", "field"),
        [
            pytest.param(ClientRegistration, {"client_id": "cid"}, "client_id", id="a registration"),
            pytest.param(IdentityMaterial, {"access_token": "at"}, "id_token", id="identity material"),
            pytest.param(
                OAuthPendingState,
                {"state": "s", "redirect_uri": "https://app.example.com/callback", "created_at": 1.0},
                "code_verifier",
                id="a pending state",
            ),
            pytest.param(TokenSet, {"access_token": "at"}, "refresh_token", id="a token set"),
        ],
    )
    def test_a_refused_change_repeats_no_value(
        self, model: type[BaseModel], payload: dict[str, object], field: str
    ) -> None:
        """Every model refuses a change, and the refusal must repeat no more than a construction does."""
        instance = model.model_validate(payload)
        value = "THE_" + "REAL_VALUE"  # pragma: allowlist secret

        with pytest.raises(ConfigurationError) as exc_info:
            setattr(instance, field, value)

        rendered = "".join(traceback.format_exception(exc_info.value))
        assert value not in rendered
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None


class TestProviderConfigResource:
    def test_a_resource_the_parser_cannot_read_names_the_field(self) -> None:
        """The resource rule reads the resource first, and the parser names an internal rather than the
        condition it refused."""
        with pytest.raises(ConfigurationError, match="resource is malformed"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://provider.example.com/authorize",
                token_url="https://provider.example.com/token",
                resource="https://[::1/resource",
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


class TestServerMetadata:
    def test_an_unknown_field_is_refused(self) -> None:
        """A caller caches discovered metadata, and a dropped field silently weakens an issuer check."""
        cached = {
            "issuer": "https://as.example.com",
            "authorize_url": "https://as.example.com/auth",
            "token_url": "https://as.example.com/token",
            "iss_param_supported": True,
        }
        with pytest.raises(ConfigurationError, match="iss_param_supported"):
            ServerMetadata.model_validate(cached)

    def test_a_url_carrying_a_credential_is_refused(self) -> None:
        """Metadata can be built by hand, so the model decides what its URLs may carry."""
        with pytest.raises(ConfigurationError, match="authorize_url must not carry userinfo"):
            ServerMetadata(
                authorize_url="https://operator:" + "sesame@auth.example.com/authorize",
                token_url="https://auth.example.com/token",
            )

    @pytest.mark.parametrize("field", [f.value for f in UrlField if f.value in ServerMetadata.model_fields])
    def test_rejects_a_credential_in_any_url_it_holds(self, field: str) -> None:
        """This model holds every URL field but the redirect URI, so one rule covers the whole list."""
        urls = {
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
        }
        urls[field] = "https://operator:" + f"sesame@auth.example.com/{field}"

        with pytest.raises(ConfigurationError, match=f"{field} must not carry userinfo"):
            ServerMetadata(**urls)


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
        with pytest.raises(ConfigurationError):
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
        with pytest.raises(ConfigurationError):
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
        assert token.extras == {}

    def test_full_token(self) -> None:
        token = TokenSet(
            access_token="access-abc",
            token_type="Bearer",
            refresh_token="refresh-xyz",
            expires_in=3600,
            expires_at=1700000000.0,
            scope="read write",
            extras={"team_id": "T123"},
        )
        assert token.refresh_token == "refresh-xyz"
        assert token.expires_in == 3600
        assert token.extras == {"team_id": "T123"}

    def test_context_defaults_to_empty_dict(self) -> None:
        token = TokenSet(access_token="access-abc")
        assert token.context == {}

    def test_context_round_trips(self) -> None:
        ctx = {"user_id": "U123", "tenant_id": "T456"}
        token = TokenSet(access_token="access-abc", context=ctx)
        assert token.context == ctx
        assert token.context["user_id"] == "U123"

    def test_extras_isolated_from_caller_mutation(self) -> None:
        original = {"team_id": "T123"}
        token = TokenSet(access_token="access-abc", extras=original)
        original["team_id"] = "mutated"
        assert token.extras["team_id"] == "T123"

    def test_context_isolated_from_caller_mutation(self) -> None:
        original = {"user_id": "U123"}
        token = TokenSet(access_token="access-abc", context=original)
        original["user_id"] = "mutated"
        assert token.context["user_id"] == "U123"

    def test_an_unknown_field_is_refused(self) -> None:
        """A token set is persisted, so a field no attribute names is data this model cannot carry."""
        with pytest.raises(ConfigurationError, match="metadata"):
            TokenSet.model_validate({"access_token": "access-abc", "metadata": {"team_id": "T123"}})

    def test_a_refused_unknown_field_does_not_repeat_its_value(self) -> None:
        with pytest.raises(ConfigurationError) as refusal:
            TokenSet.model_validate({"access_token": "access-abc", "metadata": {"team_id": "T123"}})

        assert "T123" not in str(refusal.value)

    def test_an_unknown_field_of_a_nested_user_token_is_refused(self) -> None:
        stored = {"access_token": "access-abc", "user_token": {"access_token": "xoxp", "metadata": {"id": "U1"}}}
        with pytest.raises(ConfigurationError, match="metadata"):
            TokenSet.model_validate(stored)

    def test_frozen(self) -> None:
        token = TokenSet(access_token="access-abc")
        with pytest.raises(ConfigurationError):
            token.access_token = "other"


class _Session(BaseModel):
    user: str
    tokens: FreshTokenSet


class _Sessions(BaseModel):
    tokens: list[FreshTokenSet]


class TestFreshTokenSet:
    def test_keyword_construction_builds_a_token_set(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc", extras={"id_token": "id-jwt"})
        assert isinstance(tokens, TokenSet)
        assert tokens.access_token == "access-abc"
        assert tokens.extras == {"id_token": "id-jwt"}

    def test_frozen(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc")
        with pytest.raises(ConfigurationError):
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
        fresh = FreshTokenSet(access_token="access-abc", refresh_token="refresh-xyz", extras={"id_token": "id-jwt"})
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
        with pytest.raises(ConfigurationError):
            material.access_token = "other"

    def test_from_token_set_extracts_id_token_from_extras(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc", extras={"id_token": "id-jwt"})
        material = IdentityMaterial.from_token_set(tokens)
        assert material.access_token == "access-abc"
        assert material.id_token == "id-jwt"

    def test_from_token_set_id_token_absent_is_none(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc", extras={"team_id": "T123"})
        material = IdentityMaterial.from_token_set(tokens)
        assert material.id_token is None

    def test_from_token_set_non_string_id_token_is_none(self) -> None:
        tokens = FreshTokenSet(access_token="access-abc", extras={"id_token": 12345})
        material = IdentityMaterial.from_token_set(tokens)
        assert material.id_token is None

    def test_from_token_set_omits_refresh_token_and_context(self) -> None:
        """The narrowing must not surface the refresh token or caller
        context — those fields are structurally absent from the type."""
        tokens = FreshTokenSet(
            access_token="access-abc",
            refresh_token="refresh-xyz",
            extras={"id_token": "id-jwt"},
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
        with pytest.raises(ConfigurationError):
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
        with pytest.raises(ConfigurationError, match="scope_separator must be ',' for provider Linear, got ' '"):
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
            ConfigurationError, match="can_assert_domain_ownership must be False for provider Linear, got True"
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
            ConfigurationError, match="disconnect_fully_revokes must be True for provider GitHub, got False"
        ):
            ProviderConfig(
                provider=Provider.GITHUB,
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://github.com/login/oauth/authorize",
                token_url="https://github.com/login/oauth/access_token",
                disconnect_fully_revokes=False,
            )


class TestProviderConfigRevocationHost:
    """A token is revoked where it was issued, or at another of the named provider's own hosts.

    A revocation handler sends a bearer token to ``revocation_url``, so any other host would be sent
    a token it never issued.
    """

    SLACK_OAUTH = {
        "authorize_url": "https://slack.com/oauth/v2/authorize",
        "token_url": "https://slack.com/api/oauth.v2.access",
    }

    def _config(self, **overrides: object) -> ProviderConfig:
        fields: dict[str, object] = {
            "provider": Provider.SLACK,
            "client_id": "cid",
            "client_secret": SecretStr("csec"),  # pragma: allowlist secret
            **self.SLACK_OAUTH,
        }
        fields.update(overrides)
        return ProviderConfig(**fields)  # type: ignore[arg-type]

    def test_accepts_the_token_endpoints_own_host(self) -> None:
        config = self._config(revocation_url="https://slack.com/api/auth.revoke")

        assert config.revocation_url == "https://slack.com/api/auth.revoke"

    def test_accepts_a_subdomain_of_the_token_endpoints_host(self) -> None:
        """GitHub issues at github.com and revokes at api.github.com."""
        config = ProviderConfig(
            provider=Provider.GITHUB,
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            revocation_url="https://api.github.com/applications/cid/token",
            disconnect_fully_revokes=True,
        )

        assert config.revocation_url == "https://api.github.com/applications/cid/token"

    def test_accepts_a_sibling_host_of_the_named_provider(self) -> None:
        """Google issues at googleapis.com and documents a revocation endpoint on google.com."""
        config = ProviderConfig(
            provider=Provider.GOOGLE,
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            revocation_url="https://accounts.google.com/o/oauth2/revoke",
            can_assert_domain_ownership=True,
            disconnect_fully_revokes=True,
        )

        assert config.revocation_url == "https://accounts.google.com/o/oauth2/revoke"

    def test_refuses_a_host_that_is_neither_the_token_endpoints_nor_the_providers(self) -> None:
        with pytest.raises(ConfigurationError, match="revocation_url names attacker.example.com and token_url names"):
            self._config(revocation_url="https://attacker.example.com/collect")

    def test_refuses_the_providers_revocation_host_when_the_token_endpoint_is_not_the_providers(self) -> None:
        """Both hosts must be the provider's, or a config issuing tokens elsewhere would still pass."""
        with pytest.raises(ConfigurationError, match="revocation_url names slack.com and token_url names"):
            self._config(
                token_url="https://attacker.example.com/token",
                revocation_url="https://slack.com/api/auth.revoke",
            )

    def test_refuses_a_subdomain_on_a_deployment_of_its_own(self) -> None:
        """Without the provider's hosts to fall back on, only the one host that issued the token applies."""
        with pytest.raises(ConfigurationError, match="names attacker.login.mycompany.com"):
            ProviderConfig(
                provider=Provider.SALESFORCE,
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://login.mycompany.com/services/oauth2/authorize",
                token_url="https://login.mycompany.com/services/oauth2/token",
                revocation_url="https://attacker.login.mycompany.com/services/oauth2/revoke",
            )

    def test_refuses_a_lookalike_of_the_token_endpoints_host(self) -> None:
        """The match is anchored on a label boundary, so a lookalike is not the same host."""
        with pytest.raises(ConfigurationError, match="revocation_url names evilslack.com"):
            self._config(revocation_url="https://evilslack.com/api/auth.revoke")

    def test_refuses_one_on_a_config_that_states_none_of_the_providers_hosts(self) -> None:
        """The rule cannot hang off the endpoints a caller chose, or the caller can choose past it."""
        with pytest.raises(ConfigurationError, match="revocation_url names attacker-b.example.com"):
            self._config(
                authorize_url="https://attacker-a.example.com/authorize",
                token_url="https://attacker-a.example.com/token",
                revocation_url="https://attacker-b.example.com/collect",
            )

    def test_refuses_one_where_only_the_authorization_endpoint_is_the_providers(self) -> None:
        with pytest.raises(ConfigurationError, match="revocation_url names attacker.example.com"):
            self._config(
                authorize_url="https://slack.com/oauth/v2/authorize",
                token_url="https://elsewhere.example.com/token",
                revocation_url="https://attacker.example.com/collect",
            )

    def test_the_refusal_does_not_repeat_a_credential_the_url_carried(self) -> None:
        """Whichever rule refuses it, a rejected authority can carry a credential, so none is repeated."""
        carrying = "https://operator:sesame@attacker.example.com/collect"  # pragma: allowlist secret

        with pytest.raises(ConfigurationError) as refusal:
            self._config(revocation_url=carrying)

        assert "sesame" not in str(refusal.value)

    def test_accepts_a_deployment_wholly_off_the_providers_hosts(self) -> None:
        """A Salesforce org on a custom login domain issues and revokes on that one host."""
        config = ProviderConfig(
            provider=Provider.SALESFORCE,
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            authorize_url="https://login.mycompany.com/services/oauth2/authorize",
            token_url="https://login.mycompany.com/services/oauth2/token",
            revocation_url="https://login.mycompany.com/services/oauth2/revoke",
        )

        assert config.revocation_url == "https://login.mycompany.com/services/oauth2/revoke"

    def test_accepts_any_revocation_host_when_the_config_names_no_provider(self) -> None:
        """A config naming no provider states no hosts of its own, so the caller owns the endpoint."""
        config = ProviderConfig(
            client_id="cid",
            client_secret=SecretStr("csec"),  # pragma: allowlist secret
            **self.SLACK_OAUTH,
            revocation_url="https://elsewhere.example.com/revoke",
        )

        assert config.revocation_url == "https://elsewhere.example.com/revoke"


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
        with pytest.raises(ConfigurationError):
            identity.tenancies = (TenancyContext(id="T1"),)


class TestOAuthPendingState:
    def test_a_redirect_uri_carrying_a_credential_is_refused(self) -> None:
        """A pending state is persisted and replayed, so a credential in its URI outlives the request."""
        with pytest.raises(ConfigurationError, match="redirect_uri must not carry userinfo"):
            OAuthPendingState(
                state="random-state-token",
                redirect_uri="https://operator:" + "sesame@app.example.com/callback",
                created_at=1.0,
            )

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

    def test_context_defaults_to_empty_dict(self) -> None:
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
        )
        assert state.context == {}

    def test_context_round_trips(self) -> None:
        meta = {"user_id": "U123", "tenant_id": "T456", "tool_name": "slack"}
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
            context=meta,
        )
        assert state.context == meta
        assert state.context["user_id"] == "U123"

    def test_context_isolated_from_caller_mutation(self) -> None:
        original = {"user_id": "U123"}
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
            context=original,
        )
        original["user_id"] = "mutated"
        assert state.context["user_id"] == "U123"

    def test_an_unknown_field_is_refused(self) -> None:
        """A pending state is persisted, so a field no attribute names is data this model cannot carry."""
        stored = {
            "state": "random-state-token",
            "redirect_uri": "https://app.example.com/callback",
            "created_at": 1.0,
            "metadata": {"tenant_id": "T456"},
        }
        with pytest.raises(ConfigurationError, match="metadata"):
            OAuthPendingState.model_validate(stored)

    def test_a_refused_unknown_field_does_not_repeat_its_value(self) -> None:
        stored = {
            "state": "random-state-token",
            "redirect_uri": "https://app.example.com/callback",
            "created_at": 1.0,
            "metadata": {"tenant_id": "T456"},
        }
        with pytest.raises(ConfigurationError) as refusal:
            OAuthPendingState.model_validate(stored)

        assert "T456" not in str(refusal.value)

    def test_frozen(self) -> None:
        state = OAuthPendingState(
            state="random-state-token",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
        )
        with pytest.raises(ConfigurationError):
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
        with pytest.raises(ConfigurationError, match="Linear"):
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
    """Test that a config refuses an empty separator and that no provider member states one."""

    def test_an_empty_separator_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="scope_separator must not be empty"):
            ProviderConfig(
                client_id="cid",
                client_secret=SecretStr("csec"),  # pragma: allowlist secret
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                scope_separator="",
            )

    def test_every_provider_member_states_a_usable_separator(self) -> None:
        assert [member.name for member in Provider if not member.scope_separator] == []
