"""Revocation error messages across the built-in revocation handlers.

Each message describes a failure in domain terms.
It never repeats the HTTP client's own text, which carries the request URL.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import RevocationError
from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler, StandardRevocationHandler
from apron_auth.providers import github, google, hubspot, notion, slack

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
    return config, StandardRevocationHandler()


def _preset(
    preset: Callable[..., tuple[ProviderConfig, RevocationHandler]], scopes: list[str]
) -> Callable[[], tuple[ProviderConfig, RevocationHandler]]:
    def build() -> tuple[ProviderConfig, RevocationHandler]:
        return preset(client_id="cid", client_secret="csecret", scopes=scopes)  # pragma: allowlist secret

    return build


HANDLERS: dict[str, Callable[[], tuple[ProviderConfig, RevocationHandler]]] = {
    "github": _preset(github.preset, ["read:user"]),
    "google": _preset(google.preset, ["openid"]),
    "hubspot": _preset(hubspot.preset, ["contacts"]),
    "notion": _preset(notion.preset, ["read"]),
    "slack": _preset(slack.preset, ["channels:read"]),
    "standard": _standard,
}

# NOTE: These handlers send the token in the request URL, so their errors carry no cause.
TOKEN_IN_URL = {"google", "hubspot"}


async def _revocation_error(
    name: str, httpx_mock: HTTPXMock, failure: type[httpx.RequestError] = httpx.ConnectError
) -> RevocationError:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise failure(f"{RAW_TEXT} for url {request.url}", request=request)

    httpx_mock.add_callback(refuse)
    config, handler = HANDLERS[name]()
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
@pytest.mark.parametrize("name", list(HANDLERS))
async def test_transport_error_reports_failure_kind_without_request_url(
    name: str, failure: type[httpx.RequestError], kind: str, httpx_mock: HTTPXMock
) -> None:
    error = await _revocation_error(name, httpx_mock, failure)

    assert str(error).endswith(f": {kind}")
    assert RAW_TEXT not in str(error)
    assert "https://" not in str(error)
    assert TOKEN not in str(error)


@pytest.mark.parametrize("name", sorted(set(HANDLERS) - TOKEN_IN_URL))
async def test_token_in_body_or_header_error_keeps_its_cause(name: str, httpx_mock: HTTPXMock) -> None:
    error = await _revocation_error(name, httpx_mock)

    assert isinstance(error.__cause__, httpx.ConnectError)
