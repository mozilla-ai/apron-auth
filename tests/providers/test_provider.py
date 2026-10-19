"""The ``Provider`` enum, its per-member data, and the presets that stamp it on their configs."""

from __future__ import annotations

from types import ModuleType

import pytest

from apron_auth.models import IdentityProfile, Provider, ProviderConfig
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
from apron_auth.providers.identity import infer_identity_handler

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

# The known-good facts per provider, pinned independently of the enum: display name,
# identity host suffixes, disconnect_fully_revokes, scope separator.
MODULE_FACTS: dict[Provider, tuple[str, tuple[str, ...], bool, str]] = {
    Provider.ATLASSIAN: ("Atlassian", ("auth.atlassian.com",), False, " "),
    Provider.GITHUB: ("GitHub", ("github.com",), True, " "),
    Provider.GOOGLE: ("Google", ("google.com", "googleapis.com"), True, " "),
    Provider.HUBSPOT: ("HubSpot", ("api.hubapi.com", "app.hubspot.com"), False, " "),
    Provider.LINEAR: ("Linear", ("linear.app",), False, ","),
    Provider.MICROSOFT: ("Microsoft", ("login.microsoftonline.com",), False, " "),
    Provider.NOTION: ("Notion", ("api.notion.com",), False, " "),
    Provider.SALESFORCE: ("Salesforce", ("salesforce.com",), False, " "),
    Provider.SLACK: ("Slack", ("slack.com",), False, ","),
    Provider.TYPEFORM: ("Typeform", ("api.typeform.com",), False, " "),
}


def _preset_config(module: ModuleType) -> ProviderConfig:
    config, _ = module.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
    )
    return config


def test_members_are_ordered_a_to_z() -> None:
    names = [provider.name for provider in Provider]
    assert names == sorted(names)


def test_every_built_in_provider_module_has_a_member() -> None:
    assert set(MODULES) == set(Provider)
    assert set(MODULE_FACTS) == set(Provider)


@pytest.mark.parametrize("provider", list(Provider))
def test_member_value_is_the_module_name(provider: Provider) -> None:
    assert MODULES[provider].__name__ == f"apron_auth.providers.{provider}"


@pytest.mark.parametrize("provider", list(Provider))
def test_member_data_matches_the_pinned_facts(provider: Provider) -> None:
    display_name, host_suffixes, disconnect_fully_revokes, scope_separator = MODULE_FACTS[provider]
    assert provider.display_name == display_name
    assert provider.host_suffixes == host_suffixes
    assert provider.disconnect_fully_revokes is disconnect_fully_revokes
    assert provider.scope_separator == scope_separator


@pytest.mark.parametrize("provider", list(Provider))
def test_preset_sets_the_matching_member(provider: Provider) -> None:
    config = _preset_config(MODULES[provider])
    assert config.provider is provider


@pytest.mark.parametrize("provider", list(Provider))
def test_preset_config_carries_the_member_data(provider: Provider) -> None:
    config = _preset_config(MODULES[provider])
    assert config.disconnect_fully_revokes is provider.disconnect_fully_revokes
    assert config.scope_separator == provider.scope_separator


def test_a_preset_config_may_name_a_member_its_host_suffixes_do_not_cover() -> None:
    config, _ = salesforce.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
        host="login.acme.example",
    )
    assert config.provider is Provider.SALESFORCE
    assert infer_identity_handler(config) is None


def test_hand_built_config_has_no_provider() -> None:
    config = ProviderConfig(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        authorize_url="https://example.com/authorize",
        token_url="https://example.com/token",
    )
    assert config.provider is None


def test_identity_profile_keeps_a_member_and_a_string_apart() -> None:
    built_in = IdentityProfile(provider=Provider.GOOGLE, subject="g-1")
    generic = IdentityProfile(provider="oidc:https://issuer.example", subject="s-1")
    assert built_in.provider is Provider.GOOGLE
    assert generic.provider == "oidc:https://issuer.example"
    assert built_in.identity_key() == ("google", "g-1")
