"""The ``Provider`` enum, its per-member data, and which presets label a config with a member."""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType

import pytest

from apron_auth import providers as providers_pkg
from apron_auth.mcp import to_provider_config
from apron_auth.models import Provider, ProviderConfig, ServerMetadata
from apron_auth.protocols import IdentityHandler
from apron_auth.providers import (
    atlassian,
    github,
    google,
    hubspot,
    linear,
    microsoft,
    notion,
    oidc,
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
# identity host suffixes, disconnect_fully_revokes, scope separator, identity handler class name.
MODULE_FACTS: dict[Provider, tuple[str, tuple[str, ...], bool, str, str]] = {
    Provider.ATLASSIAN: ("Atlassian", ("auth.atlassian.com",), False, " ", "AtlassianIdentityHandler"),
    Provider.GITHUB: ("GitHub", ("github.com",), True, " ", "GitHubIdentityHandler"),
    Provider.GOOGLE: ("Google", ("google.com", "googleapis.com"), True, " ", "GoogleIdentityHandler"),
    Provider.HUBSPOT: ("HubSpot", ("api.hubapi.com", "app.hubspot.com"), False, " ", "HubSpotIdentityHandler"),
    Provider.LINEAR: ("Linear", ("linear.app",), False, ",", "LinearIdentityHandler"),
    Provider.MICROSOFT: ("Microsoft", ("login.microsoftonline.com",), False, " ", "MicrosoftIdentityHandler"),
    Provider.NOTION: ("Notion", ("api.notion.com",), False, " ", "NotionIdentityHandler"),
    Provider.SALESFORCE: ("Salesforce", ("salesforce.com",), False, " ", "SalesforceIdentityHandler"),
    Provider.SLACK: ("Slack", ("slack.com",), False, ",", "SlackIdentityHandler"),
    Provider.TYPEFORM: ("Typeform", ("api.typeform.com",), False, " ", "TypeformIdentityHandler"),
}


# ``oidc`` presets any OpenID provider rather than one named provider, so it has no member.
_GENERIC_MODULE_NAMES = frozenset({"oidc"})

_GENERIC_METADATA = ServerMetadata(
    authorize_url="https://issuer.example/authorize",
    token_url="https://issuer.example/token",
    jwks_url="https://issuer.example/jwks",
    issuer="https://issuer.example",
)


def _named_provider_module_names() -> list[str]:
    names = []
    for info in pkgutil.iter_modules(providers_pkg.__path__):
        if info.name.startswith("_") or info.name in _GENERIC_MODULE_NAMES:
            continue
        module = importlib.import_module(f"{providers_pkg.__name__}.{info.name}")
        if callable(getattr(module, "preset", None)):
            names.append(info.name)
    return sorted(names)


def _preset_config(module: ModuleType) -> ProviderConfig:
    config, _ = module.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
    )
    return config


def test_members_are_ordered_a_to_z() -> None:
    names = [provider.name for provider in Provider]
    assert names == sorted(names), (
        "Declare a new member in its alphabetical position rather than appending it, so a reader "
        "knows where to look and the order does not decay."
    )


def test_the_named_provider_modules_are_exactly_the_members() -> None:
    discovered = set(_named_provider_module_names())
    members = {provider.value for provider in Provider}
    assert discovered == members, (
        "A module under apron_auth.providers that presets one named provider needs a Provider "
        f"member whose value is the module name. Modules with no member: {sorted(discovered - members)}. "
        f"Members with no module: {sorted(members - discovered)}."
    )


def test_the_fact_tables_cover_every_member() -> None:
    assert set(MODULES) == set(Provider)
    assert set(MODULE_FACTS) == set(Provider)


@pytest.mark.parametrize("provider", list(Provider))
def test_member_value_is_the_module_name(provider: Provider) -> None:
    assert MODULES[provider].__name__ == f"apron_auth.providers.{provider}"


@pytest.mark.parametrize("provider", list(Provider))
def test_member_data_matches_the_pinned_facts(provider: Provider) -> None:
    display_name, host_suffixes, disconnect_fully_revokes, scope_separator, handler_class_name = MODULE_FACTS[provider]
    assert provider.display_name == display_name
    assert provider.host_suffixes == host_suffixes
    assert provider.disconnect_fully_revokes is disconnect_fully_revokes
    assert provider.scope_separator == scope_separator
    assert provider.identity_handler_class_name == handler_class_name


@pytest.mark.parametrize("provider", list(Provider))
def test_member_builds_the_identity_handler_it_names(provider: Provider) -> None:
    handler = provider.identity_handler()
    assert isinstance(handler, getattr(MODULES[provider], provider.identity_handler_class_name))
    assert isinstance(handler, IdentityHandler)


@pytest.mark.parametrize("provider", list(Provider))
def test_member_builds_a_handler_per_call(provider: Provider) -> None:
    assert provider.identity_handler() is not provider.identity_handler()


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
    on_suffix, _ = salesforce.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
    )
    off_suffix, _ = salesforce.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
        host="login.acme.example",
    )

    assert on_suffix.provider is off_suffix.provider is Provider.SALESFORCE
    assert infer_identity_handler(on_suffix) is not None
    assert infer_identity_handler(off_suffix) is None


@pytest.mark.parametrize("provider", list(Provider))
def test_preset_follows_a_changed_member_fact(provider: Provider, monkeypatch: pytest.MonkeyPatch) -> None:
    # Patching the member proves the preset reads each fact from it rather than repeating the value.
    monkeypatch.setattr(provider, "disconnect_fully_revokes", not provider.disconnect_fully_revokes)
    monkeypatch.setattr(provider, "scope_separator", "|")

    config = _preset_config(MODULES[provider])

    assert config.disconnect_fully_revokes is provider.disconnect_fully_revokes
    assert config.scope_separator == provider.scope_separator


def test_hand_built_config_has_no_provider() -> None:
    config = ProviderConfig(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        authorize_url="https://example.com/authorize",
        token_url="https://example.com/token",
    )
    assert config.provider is None


def test_a_generic_openid_config_has_no_provider() -> None:
    config, _ = oidc.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["openid"],
        metadata=_GENERIC_METADATA,
    )
    assert config.provider is None


def test_an_mcp_config_has_no_provider() -> None:
    config = to_provider_config(_GENERIC_METADATA, client_id="cid", client_secret="csecret")
    assert config.provider is None
