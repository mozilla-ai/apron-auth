"""Revocation error messages across the built-in revocation handlers.

Each message describes a failure in domain terms.
It never repeats the HTTP client's own text, which carries the request URL.
The error never carries the failed request, which holds the token and can hold the client secret.
"""

from __future__ import annotations

import json
import traceback
from collections.abc import Callable
from urllib.parse import unquote, unquote_plus

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import RevocationError
from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler, StandardRevocationHandler
from apron_auth.providers import github, google, hubspot, notion, revocation_handler_for, slack

TOKEN = "token-SECRET-123"
RAW_TEXT = "raw transport text"


def _standard() -> tuple[ProviderConfig, RevocationHandler]:
    config = ProviderConfig(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        authorize_url="https://provider.example.com/authorize",
        token_url="https://provider.example.com/token",
        revocation_url="https://provider.example.com/revoke",
    )
    return config


def _preset(preset: Callable[..., ProviderConfig], scopes: list[str]) -> Callable[[], ProviderConfig]:
    def build() -> ProviderConfig:
        return preset(client_id="cid", client_secret="csecret", scopes=scopes)  # pragma: allowlist secret

    return build


CONFIGS: dict[str, Callable[[], ProviderConfig]] = {
    "github": _preset(github.preset, ["read:user"]),
    "google": _preset(google.preset, ["openid"]),
    "hubspot": _preset(hubspot.preset, ["contacts"]),
    "notion": _preset(notion.preset, ["read"]),
    "slack": _preset(slack.preset, ["channels:read"]),
    "standard": _standard,
}


async def _revocation_error(
    name: str, httpx_mock: HTTPXMock, failure: type[httpx.RequestError] = httpx.ConnectError
) -> RevocationError:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise failure(f"{RAW_TEXT} for url {request.url}", request=request)

    httpx_mock.add_callback(refuse)
    config = CONFIGS[name]()
    handler = revocation_handler_for(config) or StandardRevocationHandler()
    with pytest.raises(RevocationError) as exc_info:
        await handler.revoke(TOKEN, config)
    return exc_info.value


@pytest.mark.parametrize(
    ("failure", "kind"),
    [
        pytest.param(httpx.ConnectError, "network error", id="network"),
        pytest.param(httpx.ReadTimeout, "request timed out", id="timeout"),
        pytest.param(httpx.UnsupportedProtocol, "request failed", id="other"),
    ],
)
@pytest.mark.parametrize("name", list(CONFIGS))
async def test_transport_error_reports_failure_kind_without_request_url(
    name: str, failure: type[httpx.RequestError], kind: str, httpx_mock: HTTPXMock
) -> None:
    error = await _revocation_error(name, httpx_mock, failure)

    assert str(error).endswith(f": {kind}")
    assert RAW_TEXT not in str(error)
    assert "https://" not in str(error)
    assert TOKEN not in str(error)


@pytest.mark.parametrize("name", list(CONFIGS))
async def test_error_does_not_carry_the_failed_request(name: str, httpx_mock: HTTPXMock) -> None:
    error = await _revocation_error(name, httpx_mock)

    assert error.__cause__ is None
    assert error.__context__ is None
    assert TOKEN not in "".join(traceback.format_exception(error))


# NOTE: Only Slack sends the token in a header, where a token that is not ASCII cannot go.
SENDS_TOKEN_IN_HEADER = {"slack"}
NON_ASCII_TOKEN = "token-SECRET-\u20ac"


@pytest.mark.parametrize("name", sorted(SENDS_TOKEN_IN_HEADER))
async def test_token_that_cannot_be_sent_is_a_request_failure(name: str, httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(is_optional=True)
    config = CONFIGS[name]()
    handler = revocation_handler_for(config) or StandardRevocationHandler()

    with pytest.raises(RevocationError) as exc_info:
        await handler.revoke(NON_ASCII_TOKEN, config)

    assert str(exc_info.value).endswith(" token: request failed")
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert NON_ASCII_TOKEN not in "".join(traceback.format_exception(exc_info.value))
    assert httpx_mock.get_requests() == []


@pytest.mark.parametrize("name", sorted(set(CONFIGS) - SENDS_TOKEN_IN_HEADER))
async def test_token_that_is_not_ascii_reaches_the_endpoint(name: str, httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(json={"ok": True})
    config = CONFIGS[name]()
    handler = revocation_handler_for(config) or StandardRevocationHandler()

    await handler.revoke(NON_ASCII_TOKEN, config)

    request = httpx_mock.get_request()
    assert request is not None
    url = unquote(str(request.url))
    body = unquote_plus(request.content.decode())
    json_escaped = json.dumps(NON_ASCII_TOKEN)[1:-1]
    assert NON_ASCII_TOKEN in url or NON_ASCII_TOKEN in body or json_escaped in body
