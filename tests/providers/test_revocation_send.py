"""The shared revocation request every provider handler sends through."""

from __future__ import annotations

import traceback

import httpx
import pytest
from pydantic import SecretStr

from apron_auth.errors import ConfigurationError, FailureKind, RevocationError
from apron_auth.models import Provider, ProviderConfig, UrlField
from apron_auth.providers._revocation import (
    HttpMethod,
    RevocationRequest,
    StandardRevocationHandler,
    revocation_endpoint,
    send_revocation,
)

# A host that is no provider's, standing in for an endpoint chosen by someone other than the provider.
OFF_HOST_URL = "https://attacker.example.com/collect"
TOKEN = "live-access-token"  # pragma: allowlist secret


def _config(*, revokes: bool = True) -> ProviderConfig:
    return ProviderConfig(
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url="https://auth.example.com/authorize",
        token_url="https://auth.example.com/token",
        revocation_url="https://auth.example.com/revoke" if revokes else None,
    )


def _slack_config() -> ProviderConfig:
    return ProviderConfig(
        provider=Provider.SLACK,
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url="https://slack.com/oauth/v2/authorize",
        token_url="https://slack.com/api/oauth.v2.access",
        revocation_url="https://slack.com/api/auth.revoke",
    )


def _request(url: str = "https://auth.example.com/revoke", **changes: object) -> RevocationRequest:
    fields: dict[str, object] = {"url": url, "label": "Example"}
    fields.update(changes)
    return RevocationRequest(**fields)  # ty: ignore[invalid-argument-type]


def test_the_endpoint_of_a_config_that_declares_one_is_returned() -> None:
    assert revocation_endpoint(_config()) == "https://auth.example.com/revoke"


def test_a_config_declaring_no_endpoint_is_refused() -> None:
    """One sentence states this fault, rather than one copy per handler."""
    with pytest.raises(ConfigurationError, match="carries no revocation endpoint"):
        revocation_endpoint(_config(revokes=False))


def test_a_config_whose_endpoint_is_empty_is_refused() -> None:
    """The model validator refuses an empty endpoint, and ``model_copy`` does not run it."""
    bypassed = _config().model_copy(update={"revocation_url": ""})

    with pytest.raises(ConfigurationError, match="carries no revocation endpoint"):
        revocation_endpoint(bypassed)


async def test_an_empty_endpoint_is_not_reported_as_a_failure_worth_retrying() -> None:
    """A permanent fault reported as a transient one sends a caller into a retry loop it cannot leave."""
    bypassed = _config().model_copy(update={"revocation_url": ""})

    with pytest.raises(ConfigurationError) as refusal:
        await StandardRevocationHandler().revoke(TOKEN, bypassed)

    assert refusal.value.kind.retryable is False


async def test_the_response_is_returned_for_the_handler_to_read() -> None:
    """Each provider reads success its own way, so the shared send states no success rule."""
    sent: list[httpx.Request] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        def respond(request: httpx.Request) -> httpx.Response:
            sent.append(request)
            return httpx.Response(418, json={"ok": False})

        return httpx.MockTransport(respond)

    response = await send_revocation(_request(data={"token": TOKEN}), _config(), transport_factory=transport)

    assert response.status_code == 418
    assert len(sent) == 1
    assert sent[0].method == "POST"


async def test_the_transport_factory_is_the_one_injection_point() -> None:
    """A caller pinning DNS against rebinding must reach every handler's request."""
    asked: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    await send_revocation(_request(), _config(), transport_factory=transport)

    assert asked == ["https://auth.example.com/revoke"]


async def test_the_method_a_provider_states_is_the_one_sent() -> None:
    sent: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        def respond(request: httpx.Request) -> httpx.Response:
            sent.append(request.method)
            return httpx.Response(204)

        return httpx.MockTransport(respond)

    await send_revocation(_request(method=HttpMethod.DELETE), _config(), transport_factory=transport)

    assert sent == ["DELETE"]


@pytest.mark.parametrize(
    ("raised", "kind", "reason"),
    [
        (httpx.ConnectError("refused"), FailureKind.UNREACHABLE, "the endpoint could not be reached"),
        (httpx.ReadTimeout("slow"), FailureKind.TIMEOUT, "the endpoint did not answer in time"),
    ],
)
async def test_a_transport_failure_is_a_revocation_error_of_its_kind(
    raised: Exception, kind: FailureKind, reason: str
) -> None:
    """The kind decides whether a caller may send the same request again."""

    def transport(url: str) -> httpx.AsyncBaseTransport:
        def fail(request: httpx.Request) -> httpx.Response:
            raise raised

        return httpx.MockTransport(fail)

    with pytest.raises(RevocationError) as refusal:
        await send_revocation(_request(data={"token": TOKEN}), _config(), transport_factory=transport)

    assert refusal.value.kind is kind, reason


async def test_an_invalid_url_is_refused() -> None:
    """NOTE: httpx.InvalidURL sits outside httpx.HTTPError, so the broader clause does not catch it."""

    def transport(url: str) -> httpx.AsyncBaseTransport:
        def fail(request: httpx.Request) -> httpx.Response:
            raise httpx.InvalidURL("malformed")

        return httpx.MockTransport(fail)

    with pytest.raises(RevocationError) as refusal:
        await send_revocation(_request(), _config(), transport_factory=transport)

    assert refusal.value.kind is FailureKind.REFUSED
    assert "invalid URL" in str(refusal.value)


async def test_a_url_that_names_no_scheme_is_wrapped_rather_than_raised_unwrapped() -> None:
    """A caller's configuration reaches this, so no httpx error may escape as itself."""
    with pytest.raises(RevocationError) as refusal:
        await send_revocation(_request(url="not-a-url"), _config())

    assert refusal.value.kind is FailureKind.UNREACHABLE


async def test_a_token_that_cannot_go_in_a_header_is_refused_rather_than_raised_unwrapped() -> None:
    """A non-ASCII token raises outside httpx's error tree, which five of six handlers let escape."""
    with pytest.raises(RevocationError) as refusal:
        await send_revocation(_request(headers={"Authorization": "Bearer töken"}), _config())

    assert refusal.value.kind is FailureKind.REFUSED
    assert refusal.value.kind.retryable is False
    assert "could not be encoded" in str(refusal.value)
    assert "töken" not in str(refusal.value)


async def test_the_label_names_the_provider_in_the_failure() -> None:
    def transport(url: str) -> httpx.AsyncBaseTransport:
        def fail(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        return httpx.MockTransport(fail)

    with pytest.raises(RevocationError, match="Failed to revoke Example token"):
        await send_revocation(_request(), _config(), transport_factory=transport)


async def test_the_failure_neither_chains_nor_repeats_the_token() -> None:
    """The caught error holds the token-bearing request, so it must not be reachable from the refusal."""

    def transport(url: str) -> httpx.AsyncBaseTransport:
        def fail(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        return httpx.MockTransport(fail)

    with pytest.raises(RevocationError) as refusal:
        await send_revocation(
            _request(data={"token": TOKEN}, headers={"Authorization": f"Bearer {TOKEN}"}),
            _config(),
            transport_factory=transport,
        )

    rendered = "".join(traceback.format_exception(refusal.value))
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert TOKEN not in rendered


async def test_a_host_the_config_does_not_permit_is_refused_before_anything_is_sent() -> None:
    """A copy made past construction can name any endpoint, so the send path asks the rule itself."""
    asked: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    bypassed = _slack_config().model_copy(update={"revocation_url": OFF_HOST_URL})

    with pytest.raises(ConfigurationError) as refusal:
        await send_revocation(
            _request(url=OFF_HOST_URL, data={"token": TOKEN}),
            bypassed,
            transport_factory=transport,
        )

    assert asked == [], "the token must not reach a host that cannot answer for it"
    assert refusal.value.kind.retryable is False
    assert "attacker.example.com" in str(refusal.value)


async def test_a_url_built_on_another_host_is_refused_although_the_endpoint_is_the_providers() -> None:
    """A provider that builds its URL per token chooses the host it reaches, so that host is read."""
    with pytest.raises(ConfigurationError, match="attacker.example.com"):
        await send_revocation(
            _request(url=f"{OFF_HOST_URL}/{TOKEN}", endpoint="https://slack.com/api/auth.revoke"),
            _slack_config(),
        )


async def test_an_endpoint_on_another_host_is_refused_although_the_url_is_the_providers() -> None:
    """The endpoint chooses the outbound connection, so it is held to the same hosts as the URL."""
    with pytest.raises(ConfigurationError, match="attacker.example.com"):
        await send_revocation(
            _request(url="https://slack.com/api/auth.revoke", endpoint=OFF_HOST_URL),
            _slack_config(),
        )


async def test_the_refusal_does_not_repeat_a_token_the_url_carried() -> None:
    """A provider that states the token in the path sends it in the URL, so the message names the host alone."""
    with pytest.raises(ConfigurationError) as refusal:
        await send_revocation(_request(url=f"{OFF_HOST_URL}/{TOKEN}", endpoint=OFF_HOST_URL), _slack_config())

    assert TOKEN not in str(refusal.value)


async def test_a_host_the_config_permits_is_sent_to() -> None:
    asked: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    response = await send_revocation(
        _request(url="https://slack.com/api/auth.revoke", data={"token": TOKEN}),
        _slack_config(),
        transport_factory=transport,
    )

    assert response.status_code == 200
    assert asked == ["https://slack.com/api/auth.revoke"]


async def test_a_config_naming_no_provider_permits_the_host_it_reaches() -> None:
    """It names no provider whose hosts the rule could read, so its caller owns the endpoint."""
    asked: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    response = await send_revocation(
        _request(url=OFF_HOST_URL, data={"token": TOKEN}),
        _config(),
        transport_factory=transport,
    )

    assert response.status_code == 200
    assert asked == [OFF_HOST_URL]


async def test_a_cleartext_url_is_refused_before_anything_is_sent() -> None:
    """Construction requires TLS, and a copy made past it would otherwise send the token in the clear."""
    asked: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    bypassed = _slack_config().model_copy(update={"revocation_url": "http://slack.com/api/auth.revoke"})

    with pytest.raises(ConfigurationError) as refusal:
        await send_revocation(
            _request(url="http://slack.com/api/auth.revoke", data={"token": TOKEN}),
            bypassed,
            transport_factory=transport,
        )

    assert asked == [], "the token must not cross the network unprotected"
    assert refusal.value.kind.retryable is False
    assert "must state https" in str(refusal.value)


async def test_a_port_only_the_client_can_read_does_not_get_past_the_gate() -> None:
    """The gate reads the host the client dials, so a second parser's blank answer cannot wave a URL through."""
    asked: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    with pytest.raises(ConfigurationError) as refusal:
        await send_revocation(
            _request(url="http://127.0.0.1:+54321/collect", data={"token": TOKEN}),
            _slack_config(),
            transport_factory=transport,
        )

    assert asked == [], "the token must not reach a host the configuration does not permit"
    assert refusal.value.kind.retryable is False


async def test_a_cleartext_url_is_refused_on_a_config_naming_no_provider() -> None:
    """Every configuration's token needs protecting, and only a named provider has hosts to check."""
    bypassed = _config().model_copy(update={"revocation_url": "http://auth.example.com/revoke"})

    with pytest.raises(ConfigurationError, match="must state https"):
        await send_revocation(_request(url="http://auth.example.com/revoke"), bypassed)


async def test_a_cleartext_url_a_config_waived_in_code_is_sent_to() -> None:
    """A waiver stated in code is the one statement that plain HTTP is accepted for this endpoint."""
    waived = ProviderConfig.unsafe.allow_plain_http(
        UrlField.REVOCATION_URL,
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url="https://auth.example.com/authorize",
        token_url="https://auth.example.com/token",
        revocation_url="http://auth.example.com/revoke",
    )

    def transport(url: str) -> httpx.AsyncBaseTransport:
        return httpx.MockTransport(lambda request: httpx.Response(200))

    response = await send_revocation(
        _request(url="http://auth.example.com/revoke", data={"token": TOKEN}),
        waived,
        transport_factory=transport,
    )

    assert response.status_code == 200


async def test_a_loopback_url_needs_no_waiver() -> None:
    """A request to the loopback interface reaches no network, so nothing can read the token off it."""

    def transport(url: str) -> httpx.AsyncBaseTransport:
        return httpx.MockTransport(lambda request: httpx.Response(200))

    local = _config().model_copy(update={"revocation_url": "http://127.0.0.1:8080/revoke"})

    response = await send_revocation(
        _request(url="http://127.0.0.1:8080/revoke", data={"token": TOKEN}),
        local,
        transport_factory=transport,
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    "carrying",
    [
        pytest.param(
            "https://pirate:sesame@slack.com/api/auth.revoke",  # pragma: allowlist secret
            id="a user and a password",
        ),
        pytest.param("https://pirate@slack.com/api/auth.revoke", id="a user alone"),
        pytest.param("https://@slack.com/api/auth.revoke", id="the delimiter alone"),
    ],
)
async def test_a_url_carrying_a_credential_is_refused_before_anything_is_sent(carrying: str) -> None:
    """A client presents a URL's own credential in place of the token, so the token would never be revoked."""
    asked: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    bypassed = _slack_config().model_copy(update={"revocation_url": carrying})

    with pytest.raises(ConfigurationError) as refusal:
        await send_revocation(
            _request(url=carrying, headers={"Authorization": f"Bearer {TOKEN}"}),
            bypassed,
            transport_factory=transport,
        )

    assert asked == []
    assert refusal.value.kind.retryable is False
    assert "sesame" not in str(refusal.value), "a rejected authority can carry a credential"


async def test_an_authority_only_the_client_can_read_is_named_as_unreadable() -> None:
    """The refusal says which rule refused, so an operator is not sent looking at the scheme."""
    with pytest.raises(ConfigurationError, match="authority of the request to 127.0.0.1 cannot be read"):
        await send_revocation(_request(url="http://127.0.0.1:+54321/collect"), _slack_config())


async def test_a_redirect_is_not_followed() -> None:
    """A redirect would carry the token to a host no rule read, so the response is returned as it came."""
    reached: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        def respond(request: httpx.Request) -> httpx.Response:
            reached.append(str(request.url))
            return httpx.Response(302, headers={"Location": OFF_HOST_URL})

        return httpx.MockTransport(respond)

    response = await send_revocation(
        _request(url="https://slack.com/api/auth.revoke", data={"token": TOKEN}),
        _slack_config(),
        transport_factory=transport,
    )

    assert response.status_code == 302
    assert reached == ["https://slack.com/api/auth.revoke"], "the token must not follow the redirect"
