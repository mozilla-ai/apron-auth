"""The shared revocation request every provider handler sends through."""

from __future__ import annotations

import traceback

import httpx
import pytest
from pydantic import SecretStr

from apron_auth.errors import ConfigurationError, FailureKind, RevocationError
from apron_auth.models import ProviderConfig
from apron_auth.providers._revocation import (
    HttpMethod,
    RevocationRequest,
    StandardRevocationHandler,
    revocation_endpoint,
    send_revocation,
)

TOKEN = "live-access-token"  # pragma: allowlist secret


def _config(*, revokes: bool = True) -> ProviderConfig:
    return ProviderConfig(
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url="https://auth.example.com/authorize",
        token_url="https://auth.example.com/token",
        revocation_url="https://auth.example.com/revoke" if revokes else None,
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

    response = await send_revocation(_request(data={"token": TOKEN}), transport_factory=transport)

    assert response.status_code == 418
    assert len(sent) == 1
    assert sent[0].method == "POST"


async def test_the_transport_factory_is_the_one_injection_point() -> None:
    """A caller pinning DNS against rebinding must reach every handler's request."""
    asked: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    await send_revocation(_request(), transport_factory=transport)

    assert asked == ["https://auth.example.com/revoke"]


async def test_the_method_a_provider_states_is_the_one_sent() -> None:
    sent: list[str] = []

    def transport(url: str) -> httpx.AsyncBaseTransport:
        def respond(request: httpx.Request) -> httpx.Response:
            sent.append(request.method)
            return httpx.Response(204)

        return httpx.MockTransport(respond)

    await send_revocation(_request(method=HttpMethod.DELETE), transport_factory=transport)

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
        await send_revocation(_request(data={"token": TOKEN}), transport_factory=transport)

    assert refusal.value.kind is kind, reason


async def test_an_invalid_url_is_refused() -> None:
    """NOTE: httpx.InvalidURL sits outside httpx.HTTPError, so the broader clause does not catch it."""

    def transport(url: str) -> httpx.AsyncBaseTransport:
        def fail(request: httpx.Request) -> httpx.Response:
            raise httpx.InvalidURL("malformed")

        return httpx.MockTransport(fail)

    with pytest.raises(RevocationError) as refusal:
        await send_revocation(_request(), transport_factory=transport)

    assert refusal.value.kind is FailureKind.REFUSED
    assert "invalid URL" in str(refusal.value)


async def test_a_url_that_names_no_scheme_is_wrapped_rather_than_raised_unwrapped() -> None:
    """A caller's configuration reaches this, so no httpx error may escape as itself."""
    with pytest.raises(RevocationError) as refusal:
        await send_revocation(_request(url="not-a-url"))

    assert refusal.value.kind is FailureKind.UNREACHABLE


async def test_a_token_that_cannot_go_in_a_header_is_wrapped_rather_than_raised_unwrapped() -> None:
    """A non-ASCII token raises outside httpx's error tree, which five of six handlers let escape."""
    with pytest.raises(RevocationError) as refusal:
        await send_revocation(_request(headers={"Authorization": "Bearer töken"}))

    assert refusal.value.kind is FailureKind.UNEXPECTED


async def test_the_label_names_the_provider_in_the_failure() -> None:
    def transport(url: str) -> httpx.AsyncBaseTransport:
        def fail(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        return httpx.MockTransport(fail)

    with pytest.raises(RevocationError, match="Failed to revoke Example token"):
        await send_revocation(_request(), transport_factory=transport)


async def test_the_failure_neither_chains_nor_repeats_the_token() -> None:
    """The caught error holds the token-bearing request, so it must not be reachable from the refusal."""

    def transport(url: str) -> httpx.AsyncBaseTransport:
        def fail(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        return httpx.MockTransport(fail)

    with pytest.raises(RevocationError) as refusal:
        await send_revocation(
            _request(data={"token": TOKEN}, headers={"Authorization": f"Bearer {TOKEN}"}),
            transport_factory=transport,
        )

    rendered = "".join(traceback.format_exception(refusal.value))
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None
    assert TOKEN not in rendered
