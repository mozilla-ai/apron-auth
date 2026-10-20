"""The identity handler a provider configuration resolves to."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from apron_auth.errors import ConfigurationError, FailureKind
from apron_auth.models import Provider, ProviderConfig
from apron_auth.protocols import IdentityHandler
from apron_auth.providers import identity_handler_for


def _config(host: str, provider: Provider | None = None) -> ProviderConfig:
    return ProviderConfig(
        provider=provider,
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url=f"https://{host}/authorize",
        token_url=f"https://{host}/token",
    )


@pytest.mark.parametrize("provider", list(Provider))
def test_a_named_provider_resolves_the_handler_class_it_names(provider: Provider) -> None:
    handler = identity_handler_for(_config(provider.host_suffixes[0], provider))

    assert type(handler).__name__ == provider.identity_handler_class_name
    assert isinstance(handler, IdentityHandler)


@pytest.mark.parametrize("provider", list(Provider))
def test_endpoints_outside_the_named_provider_are_refused(provider: Provider) -> None:
    with pytest.raises(ConfigurationError, match=provider.display_name) as exc_info:
        identity_handler_for(_config("attacker.example.com", provider))

    assert exc_info.value.kind is FailureKind.CONFIGURATION


@pytest.mark.parametrize(
    ("authorize_host", "token_host"),
    [
        ("accounts.google.com", "attacker.example.com"),
        ("attacker.example.com", "oauth2.googleapis.com"),
    ],
)
def test_one_endpoint_on_the_provider_is_not_enough(authorize_host: str, token_host: str) -> None:
    """A config with either endpoint off the provider's hosts must not reach the handler."""
    config = ProviderConfig(
        provider=Provider.GOOGLE,
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url=f"https://{authorize_host}/authorize",
        token_url=f"https://{token_host}/token",
    )

    with pytest.raises(ConfigurationError, match="Google"):
        identity_handler_for(config)


def test_a_config_that_names_no_provider_has_no_handler() -> None:
    assert identity_handler_for(_config("accounts.google.com")) is None


def test_a_config_that_allows_no_handler_of_its_own_has_none() -> None:
    config = _config("accounts.google.com", Provider.GOOGLE).model_copy(update={"use_builtin_identity_handler": False})

    assert identity_handler_for(config) is None


def test_a_handler_is_built_per_call() -> None:
    config = _config("accounts.google.com", Provider.GOOGLE)

    assert identity_handler_for(config) is not identity_handler_for(config)
