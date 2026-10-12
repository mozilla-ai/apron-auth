"""Identity fetch error messages across the built-in handlers.

Callers log and show these messages, so they report a failure in domain terms.
They never repeat the HTTP client's own text, which carries the request URL.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityMaterial, ProviderConfig
from apron_auth.providers import (
    atlassian,
    github,
    google,
    linear,
    microsoft,
    notion,
    salesforce,
    slack,
    typeform,
)

HANDLERS: dict[str, tuple[Callable[..., tuple[ProviderConfig, object]], list[str], Callable[[], Any]]] = {
    "atlassian": (atlassian.preset, ["read:jira-work"], atlassian.AtlassianIdentityHandler),
    "github": (github.preset, ["read:user"], github.GitHubIdentityHandler),
    "google": (google.preset, ["openid"], google.GoogleIdentityHandler),
    "linear": (linear.preset, ["read"], linear.LinearIdentityHandler),
    "microsoft": (microsoft.preset, ["openid"], microsoft.MicrosoftIdentityHandler),
    "notion": (notion.preset, ["read"], notion.NotionIdentityHandler),
    "salesforce": (salesforce.preset, ["openid"], salesforce.SalesforceIdentityHandler),
    "slack-oidc": (slack.preset, ["openid"], slack.SlackIdentityHandler),
    "slack-workspace": (slack.preset, ["channels:read"], slack.SlackIdentityHandler),
    "typeform": (typeform.preset, ["accounts:read"], typeform.TypeformIdentityHandler),
}


async def _fetch_identity_error(name: str) -> IdentityFetchError:
    factory, scopes, handler_class = HANDLERS[name]
    config, _ = factory(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=scopes,
    )
    with pytest.raises(IdentityFetchError) as exc_info:
        await handler_class().fetch_identity(IdentityMaterial(access_token="access-abc"), config)
    return exc_info.value


@pytest.mark.parametrize("name", list(HANDLERS))
async def test_status_error_reports_status_code_without_request_url(name: str, httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=403, is_reusable=True)

    error = await _fetch_identity_error(name)

    assert "HTTP 403" in str(error)
    assert "https://" not in str(error)
    assert isinstance(error.__cause__, httpx.HTTPStatusError)


@pytest.mark.parametrize("name", list(HANDLERS))
async def test_transport_error_reports_failure_kind_without_request_url(name: str, httpx_mock: HTTPXMock) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"Connection refused for url {request.url}", request=request)

    httpx_mock.add_callback(refuse, is_reusable=True)

    error = await _fetch_identity_error(name)

    assert "network error" in str(error)
    assert "ConnectError" not in str(error)
    assert "https://" not in str(error)
    assert isinstance(error.__cause__, httpx.ConnectError)


@pytest.mark.parametrize("name", list(HANDLERS))
async def test_unparseable_body_omits_decoder_text(name: str, httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=200, content=b"not-json", is_reusable=True)

    error = await _fetch_identity_error(name)

    assert isinstance(error.__cause__, ValueError)
    assert str(error.__cause__) not in str(error)
