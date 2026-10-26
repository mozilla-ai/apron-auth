"""The revocation handler a provider configuration resolves to."""

from __future__ import annotations

from types import ModuleType

import pytest
from pydantic import SecretStr

from apron_auth.models import Provider, ProviderConfig
from apron_auth.protocols import RevocationHandler, StandardRevocationHandler
from apron_auth.providers import (
    atlassian,
    github,
    google,
    hubspot,
    linear,
    microsoft,
    notion,
    revocation_handler_for,
    salesforce,
    slack,
    typeform,
)

MODULES: dict[Provider, ModuleType] = {
    Provider.ATLASSIAN: atlassian,
    Provider.GITHUB: github,
    Provider.GOOGLE: google,
    Provider.HUBSPOT: hubspot,
    Provider.LINEAR: linear,
    Provider.MICROSOFT: microsoft,
    Provider.NOTION: notion,
    Provider.SALESFORCE: salesforce,
    Provider.SLACK: slack,
    Provider.TYPEFORM: typeform,
}


def _config(provider: Provider | None, *, host: str = "provider.example.com", revokes: bool = True) -> ProviderConfig:
    """Build a config whose endpoints sit on one host, so the revocation host rule is satisfied."""
    return ProviderConfig(
        provider=provider,
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url=f"https://{host}/authorize",
        token_url=f"https://{host}/token",
        revocation_url=f"https://{host}/revoke" if revokes else None,
        disconnect_fully_revokes=provider.disconnect_fully_revokes if provider else False,
        can_assert_domain_ownership=provider.can_assert_domain_ownership if provider else False,
        scope_separator=provider.scope_separator if provider else " ",
    )


@pytest.mark.parametrize("provider", list(Provider))
def test_it_resolves_what_the_provider_preset_pairs_with_its_config(provider: Provider) -> None:
    """The resolver must answer what the preset answers, or resolving would change where a token goes."""
    config, paired = MODULES[provider].preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
    )

    resolved = revocation_handler_for(config)

    assert type(resolved) is type(paired)


@pytest.mark.parametrize("provider", [p for p in Provider if p.revocation_handler_class_name is not None])
def test_a_member_naming_a_class_resolves_that_class(provider: Provider) -> None:
    handler = revocation_handler_for(_config(provider))

    assert type(handler).__name__ == provider.revocation_handler_class_name
    assert isinstance(handler, RevocationHandler)


@pytest.mark.parametrize("provider", [p for p in Provider if p.revocation_handler_class_name is None])
def test_a_member_naming_no_class_resolves_the_standard_handler(provider: Provider) -> None:
    """The provider needs nothing of its own, so RFC 7009 revocation applies."""
    handler = revocation_handler_for(_config(provider))

    assert isinstance(handler, StandardRevocationHandler)


@pytest.mark.parametrize("provider", list(Provider))
def test_a_config_with_no_revocation_endpoint_resolves_no_handler(provider: Provider) -> None:
    """There is nowhere to send the request, so there is no handler to send it."""
    assert revocation_handler_for(_config(provider, revokes=False)) is None


def test_a_config_that_names_no_provider_resolves_no_handler() -> None:
    assert revocation_handler_for(_config(None)) is None


def test_a_handler_is_built_per_call() -> None:
    config = _config(Provider.SLACK)

    assert revocation_handler_for(config) is not revocation_handler_for(config)


def test_a_named_class_that_is_not_a_handler_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A member naming a class that revokes nothing is a defect in this library, not in the config."""

    class NotAHandler:
        pass

    monkeypatch.setattr("apron_auth.providers.slack.SlackRevocationHandler", NotAHandler)

    with pytest.raises(TypeError, match="SlackRevocationHandler is not a revocation handler"):
        revocation_handler_for(_config(Provider.SLACK))


def test_a_name_the_module_does_not_define_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A member naming a class that is not there is a defect in this library, not in the config."""
    monkeypatch.delattr("apron_auth.providers.slack.SlackRevocationHandler")

    with pytest.raises(TypeError, match="defines no SlackRevocationHandler"):
        revocation_handler_for(_config(Provider.SLACK))
