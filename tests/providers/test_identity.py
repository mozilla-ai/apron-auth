"""The identity handler a provider configuration resolves to."""

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.errors import ConfigurationError, FailureKind, IdentityFetchError
from apron_auth.models import IdentityMaterial, Provider, ProviderConfig
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
    config = _config("accounts.google.com", Provider.GOOGLE).with_changes(use_builtin_identity_handler=False)

    assert identity_handler_for(config) is None


def test_a_named_class_that_is_not_a_handler_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A member naming a class that fetches no identity is a defect in this library, not in the config."""

    class NotAHandler:
        pass

    monkeypatch.setattr("apron_auth.providers.google.GoogleIdentityHandler", NotAHandler)

    with pytest.raises(TypeError, match="GoogleIdentityHandler is not an identity handler"):
        identity_handler_for(_config("accounts.google.com", Provider.GOOGLE))


def test_a_name_the_module_does_not_define_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A member naming a class that is not there is a defect in this library, not in the config."""
    monkeypatch.delattr("apron_auth.providers.google.GoogleIdentityHandler")

    with pytest.raises(TypeError, match="defines no GoogleIdentityHandler"):
        identity_handler_for(_config("accounts.google.com", Provider.GOOGLE))


def test_a_config_that_allows_no_handler_is_not_host_checked() -> None:
    """A deployment on other hosts opts out without being told its endpoints are wrong."""
    config = _config("login.acme.example", Provider.SALESFORCE).with_changes(use_builtin_identity_handler=False)

    assert identity_handler_for(config) is None


def test_a_handler_is_built_per_call() -> None:
    config = _config("accounts.google.com", Provider.GOOGLE)

    assert identity_handler_for(config) is not identity_handler_for(config)


@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
@pytest.mark.parametrize("provider", list(Provider), ids=lambda provider: provider.value)
async def test_every_resolved_handler_runs_on_the_callers_transport(provider: Provider, httpx_mock: HTTPXMock) -> None:
    """A request carrying the access token reaches the provider on the connection the caller shaped.

    Two things are asserted, because a handler can fail either half: one that asks for no transport
    sends its request anyway, and one that asks and then builds its client without the answer sends
    it somewhere the caller never shaped. The mock answers whatever the caller's transport did not,
    so the second half fails as an assertion rather than as a real request.
    """
    asked: list[str] = []
    reached: list[httpx.Request] = []

    def through_the_callers_transport(request: httpx.Request) -> httpx.Response:
        reached.append(request)
        return httpx.Response(500, json={})

    def factory(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return httpx.MockTransport(through_the_callers_transport)

    httpx_mock.add_response(json={}, is_reusable=True)
    config = _config(provider.host_suffixes[0], provider)
    handler = identity_handler_for(config, transport_factory=factory)
    assert handler is not None

    with pytest.raises(IdentityFetchError):
        await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

    assert asked, f"the {provider.display_name} handler asked for no transport"
    assert reached, f"the {provider.display_name} handler asked for a transport and sent its request elsewhere"


@pytest.mark.parametrize("provider", list(Provider), ids=lambda provider: provider.value)
async def test_a_factory_that_refuses_stops_every_resolved_handler(provider: Provider) -> None:
    """The fault is the caller's policy rather than the provider's, so the same request fails the same way."""

    def refusing_factory(url: str) -> httpx.AsyncBaseTransport:
        msg = "refused by policy"
        raise RuntimeError(msg)

    config = _config(provider.host_suffixes[0], provider)
    handler = identity_handler_for(config, transport_factory=refusing_factory)
    assert handler is not None

    with pytest.raises(IdentityFetchError) as refusal:
        await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

    assert refusal.value.kind is FailureKind.UNEXPECTED
    assert refusal.value.retryable is False
