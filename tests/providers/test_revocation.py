"""The revocation handler a provider configuration resolves to."""

from __future__ import annotations

import traceback
from collections.abc import Callable
from types import ModuleType

import httpx
import pytest
from pydantic import SecretStr

from apron_auth.errors import ConfigurationError, FailureKind, RevocationError
from apron_auth.models import Provider, ProviderConfig
from apron_auth.protocols import RevocationHandler
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
from apron_auth.providers._revocation import StandardRevocationHandler

TOKEN = "live-access-token"  # pragma: allowlist secret

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


def _config(provider: Provider | None, *, host: str | None = None, revokes: bool = True) -> ProviderConfig:
    """Build a config whose endpoints sit on one of the provider's own hosts, as its preset's do."""
    host = host or (provider.host_suffixes[0] if provider else "provider.example.com")
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
def test_it_resolves_the_class_the_member_names_for_a_preset_config(provider: Provider) -> None:
    """A preset's own endpoints must reach the handler its member names, or revocation changes hands."""
    config = MODULES[provider].preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
    )

    resolved = revocation_handler_for(config)

    if provider.revocation_handler_class_name is not None:
        assert type(resolved).__name__ == provider.revocation_handler_class_name
    elif config.revocation_url is None:
        assert resolved is None
    else:
        assert isinstance(resolved, StandardRevocationHandler)


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


@pytest.mark.parametrize("provider", list(Provider))
def test_a_config_whose_revocation_endpoint_is_empty_resolves_no_handler(provider: Provider) -> None:
    """An empty endpoint is no endpoint, and ``model_copy`` reaches here without the validator that refuses it."""
    bypassed = _config(provider).model_copy(update={"revocation_url": ""})

    assert revocation_handler_for(bypassed) is None


def test_endpoints_outside_a_provider_that_names_a_class_are_refused() -> None:
    """A provider's own handler may put the token in the request line, so it runs on that host alone."""
    config = _config(Provider.HUBSPOT, host="oauth.acme.test")

    with pytest.raises(ConfigurationError, match="HubSpot"):
        revocation_handler_for(config)


def test_endpoints_outside_a_provider_taking_rfc_7009_still_resolve() -> None:
    """RFC 7009 states the token in the body and reads no host, so a deployment of its own keeps it."""
    config = _config(Provider.SALESFORCE, host="login.mycompany.com")

    assert isinstance(revocation_handler_for(config), StandardRevocationHandler)


def test_a_config_that_names_no_provider_resolves_no_handler() -> None:
    assert revocation_handler_for(_config(None)) is None


@pytest.mark.parametrize("provider", [p for p in Provider if p.revocation_handler_class_name is not None])
async def test_a_providers_own_handler_reaches_the_transport_factory(provider: Provider) -> None:
    """A caller pinning DNS against rebinding reaches every handler, not only the RFC 7009 one."""
    pinned: list[str] = []

    def factory(url: str) -> httpx.MockTransport:
        pinned.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))

    config = _config(provider)
    handler = revocation_handler_for(config, transport_factory=factory)
    assert handler is not None

    await handler.revoke("a-token", config)

    # The factory is asked for the token-free endpoint, which prefixes the per-token URL HubSpot sends to.
    assert config.revocation_url is not None
    assert len(pinned) == 1
    assert pinned[0].startswith(config.revocation_url)


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


def _failing_transport(exc: Exception) -> Callable[[str], httpx.MockTransport]:
    def factory(url: str) -> httpx.MockTransport:
        def fail(request: httpx.Request) -> httpx.Response:
            raise exc

        return httpx.MockTransport(fail)

    return factory


def _answering_transport(status_code: int) -> Callable[[str], httpx.MockTransport]:
    def factory(url: str) -> httpx.MockTransport:
        return httpx.MockTransport(lambda request: httpx.Response(status_code, json={"ok": False}))

    return factory


@pytest.mark.parametrize("provider", list(Provider))
async def test_every_handler_reports_a_transport_failure_alike(provider: Provider) -> None:
    """Five handlers of six once differed here, so this states the one shape they now share."""
    config = _config(provider)
    handler = revocation_handler_for(config, transport_factory=_failing_transport(httpx.ConnectError("refused")))
    assert handler is not None

    with pytest.raises(RevocationError) as refusal:
        await handler.revoke(TOKEN, config)

    assert refusal.value.kind is FailureKind.UNREACHABLE
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert TOKEN not in "".join(traceback.format_exception(refusal.value))


@pytest.mark.parametrize("provider", list(Provider))
async def test_every_handler_refuses_an_invalid_url_alike(provider: Provider) -> None:
    """NOTE: httpx.InvalidURL sits outside httpx.HTTPError, and five handlers of six let it escape."""
    config = _config(provider)
    handler = revocation_handler_for(config, transport_factory=_failing_transport(httpx.InvalidURL("malformed")))
    assert handler is not None

    with pytest.raises(RevocationError) as refusal:
        await handler.revoke(TOKEN, config)

    assert refusal.value.kind is FailureKind.REFUSED


@pytest.mark.parametrize("provider", list(Provider))
async def test_no_handler_lets_a_server_error_escape_as_itself(provider: Provider) -> None:
    """Each provider reads a status its own way, and none of them answers with an HTTP library's error."""
    config = _config(provider)
    handler = revocation_handler_for(config, transport_factory=_answering_transport(500))
    assert handler is not None

    try:
        outcome = await handler.revoke(TOKEN, config)
    except RevocationError as refusal:
        assert refusal.kind is FailureKind.SERVER_ERROR
    else:
        assert outcome is False


@pytest.mark.parametrize("provider", list(Provider))
async def test_every_handler_refuses_a_config_declaring_no_endpoint_alike(provider: Provider) -> None:
    """The resolver answers None before a handler is built, so the handler states this for a direct caller."""
    resolved = revocation_handler_for(_config(provider))
    assert resolved is not None
    handler = type(resolved)()

    with pytest.raises(ConfigurationError, match="carries no revocation endpoint"):
        await handler.revoke(TOKEN, _config(provider, revokes=False))


@pytest.mark.parametrize("provider", list(Provider))
async def test_no_handler_hands_the_token_to_the_transport_factory(provider: Provider) -> None:
    """A factory is caller-supplied code that may log what it pinned, so the token must not reach it."""
    seen: list[str] = []

    def factory(url: str) -> httpx.MockTransport:
        seen.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))

    config = _config(provider)
    handler = revocation_handler_for(config, transport_factory=factory)
    assert handler is not None

    await handler.revoke(TOKEN, config)

    assert seen
    assert TOKEN not in seen[0]


@pytest.mark.parametrize("provider", list(Provider))
async def test_a_transport_factory_that_refuses_does_not_escape_as_itself(provider: Provider) -> None:
    """A factory refusing a private address names the URL it refused, which must not reach a caller raw."""

    def refusing(url: str) -> httpx.MockTransport:
        msg = f"refusing to connect to {url}"
        raise RuntimeError(msg)

    config = _config(provider)
    handler = revocation_handler_for(config, transport_factory=refusing)
    assert handler is not None

    with pytest.raises(RevocationError) as refusal:
        await handler.revoke(TOKEN, config)

    assert refusal.value.kind is FailureKind.UNEXPECTED
    assert TOKEN not in "".join(traceback.format_exception(refusal.value))
