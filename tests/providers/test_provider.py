"""The ``Provider`` enum, its per-member data, and which presets label a config with a member."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from types import ModuleType
from typing import TYPE_CHECKING, Any

import pytest
from support import VaryFacts

from apron_auth import providers as providers_pkg
from apron_auth.errors import ConfigurationError
from apron_auth.mcp import to_provider_config
from apron_auth.models import ClientRegistration, Provider, ProviderConfig, ProviderFacts, ServerMetadata
from apron_auth.protocols import IdentityHandler, RevocationHandler
from apron_auth.providers import (
    atlassian,
    github,
    google,
    hubspot,
    identity_handler_for,
    linear,
    microsoft,
    notion,
    oidc,
    salesforce,
    slack,
    typeform,
)
from apron_auth.providers._host_match import oauth_hosts_match

if TYPE_CHECKING:
    from collections.abc import Callable

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

# Every preset this library offers, including the two no Provider member names.
PRESETS: dict[str, Callable[..., Any]] = {
    **{f"{provider.value}.preset": MODULES[provider].preset for provider in Provider},
    "oidc.preset": oidc.preset,
    "slack.sign_in_preset": slack.sign_in_preset,
}

# The known-good facts per provider, pinned independently of the enum, so a slip in a member's
# declaration fails a test rather than shipping, including one that moves where a token may be sent.
MODULE_FACTS: dict[Provider, ProviderFacts] = {
    Provider.ATLASSIAN: ProviderFacts(
        can_assert_domain_ownership=False,
        disconnect_fully_revokes=False,
        display_name="Atlassian",
        host_suffixes=("auth.atlassian.com",),
        identity_handler_class_name="AtlassianIdentityHandler",
        revocation_handler_class_name=None,
        scope_separator=" ",
        user_token_response_field=None,
    ),
    Provider.GITHUB: ProviderFacts(
        can_assert_domain_ownership=False,
        disconnect_fully_revokes=True,
        display_name="GitHub",
        host_suffixes=("github.com",),
        identity_handler_class_name="GitHubIdentityHandler",
        revocation_handler_class_name="GitHubRevocationHandler",
        scope_separator=" ",
        user_token_response_field=None,
    ),
    Provider.GOOGLE: ProviderFacts(
        can_assert_domain_ownership=True,
        disconnect_fully_revokes=True,
        display_name="Google",
        host_suffixes=("google.com", "googleapis.com"),
        identity_handler_class_name="GoogleIdentityHandler",
        revocation_handler_class_name="GoogleRevocationHandler",
        scope_separator=" ",
        user_token_response_field=None,
    ),
    Provider.HUBSPOT: ProviderFacts(
        can_assert_domain_ownership=False,
        disconnect_fully_revokes=False,
        display_name="HubSpot",
        host_suffixes=("api.hubapi.com", "app.hubspot.com"),
        identity_handler_class_name="HubSpotIdentityHandler",
        revocation_handler_class_name="HubSpotRevocationHandler",
        scope_separator=" ",
        user_token_response_field=None,
    ),
    Provider.LINEAR: ProviderFacts(
        can_assert_domain_ownership=False,
        disconnect_fully_revokes=False,
        display_name="Linear",
        host_suffixes=("linear.app",),
        identity_handler_class_name="LinearIdentityHandler",
        revocation_handler_class_name=None,
        scope_separator=",",
        user_token_response_field=None,
    ),
    Provider.MICROSOFT: ProviderFacts(
        can_assert_domain_ownership=True,
        disconnect_fully_revokes=False,
        display_name="Microsoft",
        host_suffixes=("login.microsoftonline.com",),
        identity_handler_class_name="MicrosoftIdentityHandler",
        revocation_handler_class_name=None,
        scope_separator=" ",
        user_token_response_field=None,
    ),
    Provider.NOTION: ProviderFacts(
        can_assert_domain_ownership=False,
        disconnect_fully_revokes=False,
        display_name="Notion",
        host_suffixes=("api.notion.com",),
        identity_handler_class_name="NotionIdentityHandler",
        revocation_handler_class_name="NotionRevocationHandler",
        scope_separator=" ",
        user_token_response_field=None,
    ),
    Provider.SALESFORCE: ProviderFacts(
        can_assert_domain_ownership=False,
        disconnect_fully_revokes=False,
        display_name="Salesforce",
        host_suffixes=("salesforce.com",),
        identity_handler_class_name="SalesforceIdentityHandler",
        revocation_handler_class_name=None,
        scope_separator=" ",
        user_token_response_field=None,
    ),
    Provider.SLACK: ProviderFacts(
        can_assert_domain_ownership=False,
        disconnect_fully_revokes=False,
        display_name="Slack",
        host_suffixes=("slack.com",),
        identity_handler_class_name="SlackIdentityHandler",
        revocation_handler_class_name="SlackRevocationHandler",
        scope_separator=",",
        user_token_response_field="authed_user",
    ),
    Provider.TYPEFORM: ProviderFacts(
        can_assert_domain_ownership=False,
        disconnect_fully_revokes=False,
        display_name="Typeform",
        host_suffixes=("api.typeform.com",),
        identity_handler_class_name="TypeformIdentityHandler",
        revocation_handler_class_name=None,
        scope_separator=" ",
        user_token_response_field=None,
    ),
}


# ``oidc`` presets any OpenID provider rather than one named provider, so it has no member.
_GENERIC_MODULE_NAMES = frozenset({"oidc"})

_GENERIC_METADATA = ServerMetadata(
    authorize_url="https://issuer.example/authorize",
    token_url="https://issuer.example/token",
    jwks_url="https://issuer.example/jwks",
    issuer="https://issuer.example",
)

# Values each preset accepts, so a test can vary one thing at a time against all of them.
_VALID_KWARGS: dict[str, dict[str, Any]] = {
    "oidc.preset": {"scopes": ["dummy"], "metadata": _GENERIC_METADATA},
    "slack.sign_in_preset": {"scopes": ["email"]},
}


def _valid_kwargs(name: str) -> dict[str, Any]:
    """Return the keywords a preset accepts, so only the value under test differs between them.

    The mapping is fresh per call, because a caller sets the value under test on it.
    """
    return dict(_VALID_KWARGS.get(name, {"scopes": ["dummy"]}))


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
    config = module.preset(
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


def test_public_provider_modules_expose_a_preset() -> None:
    missing_preset: list[str] = []
    for info in pkgutil.iter_modules(providers_pkg.__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{providers_pkg.__name__}.{info.name}")
        if not callable(getattr(module, "preset", None)):
            missing_preset.append(info.name)

    assert not missing_preset, (
        "A public module under apron_auth.providers presets a provider and exposes preset(...). "
        f"Rename a helper module with a leading underscore. Modules with no preset: {', '.join(missing_preset)}."
    )


def test_the_named_provider_modules_are_exactly_the_members() -> None:
    discovered = set(_named_provider_module_names())
    members = {provider.value for provider in Provider}
    assert discovered == members, (
        "A module under apron_auth.providers that presets one named provider needs a Provider "
        f"member whose value is the module name. Modules with no member: {sorted(discovered - members)}. "
        f"Members with no module: {sorted(members - discovered)}."
    )


@pytest.mark.parametrize("name", sorted(PRESETS))
def test_every_preset_refuses_a_bare_string_of_scopes(name: str) -> None:
    """A string is a sequence of characters, so taking one would request each letter as a scope."""
    kwargs = _valid_kwargs(name)
    kwargs["scopes"] = " ".join(kwargs["scopes"])

    with pytest.raises(ConfigurationError, match="scopes must be a sequence of scope strings"):
        PRESETS[name]("cid", "csecret", **kwargs)  # pragma: allowlist secret


@pytest.mark.parametrize("name", sorted(PRESETS))
def test_every_preset_accepts_any_sequence_of_scopes(name: str) -> None:
    """The shared builder takes a Sequence, so a preset must not demand a list of its caller."""
    kwargs = _valid_kwargs(name)
    kwargs["scopes"] = tuple(kwargs["scopes"])

    config = PRESETS[name]("cid", "csecret", **kwargs)  # pragma: allowlist secret

    assert isinstance(config, ProviderConfig)


@pytest.mark.parametrize("name", sorted(PRESETS))
def test_every_preset_takes_two_positionals_and_the_rest_by_keyword(name: str) -> None:
    """A positional call that reads correctly against one preset must not mean something else against another."""
    params = list(inspect.signature(PRESETS[name]).parameters.values())
    positional = [p.name for p in params if p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD]
    keyword_only = {p.name for p in params if p.kind is inspect.Parameter.KEYWORD_ONLY}

    assert positional == ["client_id", "client_secret"]
    assert {"scopes", "redirect_uri", "extra_params"} <= keyword_only


# A value each provider-specific keyword refuses, so one class covers a fault in any of them.
_REFUSED_SPECIFIC_KWARGS: dict[str, dict[str, Any]] = {
    "salesforce.preset": {"host": "https://login.salesforce.com/"},
    "slack.preset": {"user_scopes": ["openid"]},
    "slack.sign_in_preset": {"scopes": ["chat:write"]},
}


@pytest.mark.parametrize("name", sorted(_REFUSED_SPECIFIC_KWARGS))
def test_a_fault_in_a_provider_specific_keyword_is_a_configuration_error(name: str) -> None:
    """A provider-specific keyword is still something a caller passed, so its fault is the same class."""
    with pytest.raises(ConfigurationError):
        PRESETS[name]("cid", "csecret", **{**_valid_kwargs(name), **_REFUSED_SPECIFIC_KWARGS[name]})


@pytest.mark.parametrize("name", sorted(PRESETS))
def test_every_preset_refuses_a_reserved_authorization_parameter_as_a_configuration_error(name: str) -> None:
    """A fault in what a caller passed is one class, so one except clause covers every preset."""
    with pytest.raises(ConfigurationError):
        PRESETS[name]("cid", "csecret", extra_params={"state": "forged"}, **_valid_kwargs(name))


@pytest.mark.parametrize("name", sorted(PRESETS))
def test_no_preset_raises_a_value_error_for_a_fault_in_what_it_was_passed(name: str) -> None:
    """ConfigurationError does not inherit from ValueError, so a caller catching one misses the other."""
    try:
        PRESETS[name]("cid", "csecret", extra_params={"state": "forged"}, **_valid_kwargs(name))
    except ConfigurationError:
        return
    except ValueError as error:  # pragma: no cover - the assertion reports the class
        pytest.fail(f"{name} raised {type(error).__name__}, not ConfigurationError")


def test_the_fact_tables_cover_every_member() -> None:
    assert set(MODULES) == set(Provider)
    assert set(MODULE_FACTS) == set(Provider)


@pytest.mark.parametrize("provider", list(Provider))
def test_member_value_is_the_module_name(provider: Provider) -> None:
    assert MODULES[provider].__name__ == f"apron_auth.providers.{provider}"


@pytest.mark.parametrize("provider", list(Provider))
def test_member_data_matches_the_pinned_facts(provider: Provider) -> None:
    pinned = MODULE_FACTS[provider]
    assert provider.display_name == pinned.display_name
    assert provider.host_suffixes == pinned.host_suffixes
    assert provider.disconnect_fully_revokes is pinned.disconnect_fully_revokes
    assert provider.scope_separator == pinned.scope_separator
    assert provider.identity_handler_class_name == pinned.identity_handler_class_name
    assert provider.revocation_handler_class_name == pinned.revocation_handler_class_name
    assert provider.can_assert_domain_ownership is pinned.can_assert_domain_ownership


@pytest.mark.parametrize("provider", list(Provider))
@pytest.mark.parametrize(
    "fact",
    [
        "can_assert_domain_ownership",
        "disconnect_fully_revokes",
        "display_name",
        "host_suffixes",
        "identity_handler_class_name",
        "revocation_handler_class_name",
        "scope_separator",
        "user_token_response_field",
    ],
)
def test_a_members_fact_cannot_be_assigned(provider: Provider, fact: str) -> None:
    """A member's facts decide where an access token may be sent, so no caller may change one."""
    with pytest.raises(AttributeError):
        setattr(provider, fact, "whatever")

    assert getattr(provider, fact) == getattr(MODULE_FACTS[provider], fact)


@pytest.mark.parametrize("provider", list(Provider))
def test_member_names_an_identity_handler_its_module_defines(provider: Provider) -> None:
    handler_class = getattr(MODULES[provider], provider.identity_handler_class_name, None)
    assert handler_class is not None, f"{MODULES[provider].__name__} defines no {provider.identity_handler_class_name}."
    assert isinstance(handler_class(), IdentityHandler)


@pytest.mark.parametrize("provider", [p for p in Provider if p.revocation_handler_class_name is not None])
def test_member_names_a_revocation_handler_its_module_defines(provider: Provider) -> None:
    name = provider.revocation_handler_class_name
    handler_class = getattr(MODULES[provider], name, None)
    assert handler_class is not None, f"{MODULES[provider].__name__} defines no {name}."
    assert isinstance(handler_class(), RevocationHandler)


@pytest.mark.parametrize("provider", list(Provider))
def test_preset_sets_the_matching_member(provider: Provider) -> None:
    config = _preset_config(MODULES[provider])
    assert config.provider is provider


@pytest.mark.parametrize("provider", list(Provider))
def test_a_preset_config_resolves_the_member_handler(provider: Provider) -> None:
    """The preset's own endpoints must satisfy the host condition its member states."""
    handler = identity_handler_for(_preset_config(MODULES[provider]))

    assert type(handler).__name__ == provider.identity_handler_class_name


@pytest.mark.parametrize("provider", list(Provider))
def test_preset_config_carries_the_member_data(provider: Provider) -> None:
    config = _preset_config(MODULES[provider])
    assert config.can_assert_domain_ownership is provider.can_assert_domain_ownership
    assert config.disconnect_fully_revokes is provider.disconnect_fully_revokes
    assert config.scope_separator == provider.scope_separator


def test_a_preset_config_may_name_a_member_its_host_suffixes_do_not_cover() -> None:
    on_suffix = salesforce.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
    )
    off_suffix = salesforce.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
        host="login.acme.example",
    )

    assert on_suffix.provider is off_suffix.provider is Provider.SALESFORCE
    assert oauth_hosts_match(on_suffix, Provider.SALESFORCE.host_suffixes)
    assert not oauth_hosts_match(off_suffix, Provider.SALESFORCE.host_suffixes)


@pytest.mark.parametrize("provider", list(Provider))
def test_preset_follows_a_changed_member_fact(provider: Provider, vary_facts: VaryFacts) -> None:
    # Varying the facts proves the preset reads each one from the member rather than repeating the value.
    vary_facts(
        provider,
        can_assert_domain_ownership=not provider.can_assert_domain_ownership,
        disconnect_fully_revokes=not provider.disconnect_fully_revokes,
        scope_separator="|",
    )

    config = _preset_config(MODULES[provider])

    assert config.can_assert_domain_ownership is provider.can_assert_domain_ownership
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
    config = oidc.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["openid"],
        metadata=_GENERIC_METADATA,
    )
    assert config.provider is None


def test_an_mcp_config_has_no_provider() -> None:
    config = to_provider_config(_GENERIC_METADATA, ClientRegistration(client_id="cid", client_secret="csecret"))
    assert config.provider is None
