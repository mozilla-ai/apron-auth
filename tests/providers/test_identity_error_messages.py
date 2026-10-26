"""Identity fetch errors across the built-in handlers.

Each message describes a failure in domain terms.
It never repeats the HTTP client's own text, which carries the request URL.
The error never chains the failed request, which carries the access token, or the decoder's error.
"""

from __future__ import annotations

import json
import traceback
from collections.abc import Callable
from functools import partial
from typing import NamedTuple

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityMaterial, ProviderConfig, ServerMetadata
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

ACCESS_TOKEN = "access-SECRET-xyz"  # pragma: allowlist secret

_OIDC_METADATA = ServerMetadata(
    authorize_url="https://sso.example.com/auth",
    token_url="https://sso.example.com/token",
    issuer="https://sso.example.com",
    userinfo_url="https://sso.example.com/userinfo",
    jwks_url="https://sso.example.com/certs",
)


class _HandlerCase(NamedTuple):
    preset: Callable[..., ProviderConfig]
    scopes: list[str]
    handler: Callable[[], IdentityHandler]


HANDLERS: dict[str, _HandlerCase] = {
    "atlassian": _HandlerCase(atlassian.preset, ["read:jira-work"], atlassian.AtlassianIdentityHandler),
    "github": _HandlerCase(github.preset, ["read:user"], github.GitHubIdentityHandler),
    "google": _HandlerCase(google.preset, ["openid"], google.GoogleIdentityHandler),
    "hubspot": _HandlerCase(hubspot.preset, ["contacts"], hubspot.HubSpotIdentityHandler),
    "linear": _HandlerCase(linear.preset, ["read"], linear.LinearIdentityHandler),
    "microsoft": _HandlerCase(microsoft.preset, ["openid"], microsoft.MicrosoftIdentityHandler),
    "notion": _HandlerCase(notion.preset, ["read"], notion.NotionIdentityHandler),
    "oidc": _HandlerCase(
        partial(oidc.preset, metadata=_OIDC_METADATA),
        ["openid"],
        partial(oidc.identity_handler, _OIDC_METADATA),
    ),
    "salesforce": _HandlerCase(salesforce.preset, ["openid"], salesforce.SalesforceIdentityHandler),
    "slack-oidc": _HandlerCase(slack.sign_in_preset, ["openid"], slack.SlackIdentityHandler),
    "slack-workspace": _HandlerCase(slack.preset, ["channels:read"], slack.SlackIdentityHandler),
    "typeform": _HandlerCase(typeform.preset, ["accounts:read"], typeform.TypeformIdentityHandler),
}


async def _fetch_identity_error(name: str) -> IdentityFetchError:
    case = HANDLERS[name]
    config = case.preset(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=case.scopes,
    )
    with pytest.raises(IdentityFetchError) as exc_info:
        await case.handler().fetch_identity(IdentityMaterial(access_token=ACCESS_TOKEN), config)
    return exc_info.value


def _assert_unchained(error: IdentityFetchError) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert ACCESS_TOKEN not in "".join(traceback.format_exception(error))


@pytest.mark.parametrize("name", list(HANDLERS))
async def test_status_error_reports_status_code_without_request_url(name: str, httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=403, is_reusable=True)

    error = await _fetch_identity_error(name)

    assert "HTTP 403" in str(error)
    assert "https://" not in str(error)
    _assert_unchained(error)


@pytest.mark.parametrize("name", list(HANDLERS))
async def test_transport_error_reports_failure_kind_without_request_url(name: str, httpx_mock: HTTPXMock) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"Connection refused for url {request.url}", request=request)

    httpx_mock.add_callback(refuse, is_reusable=True)

    error = await _fetch_identity_error(name)

    assert "network error" in str(error)
    assert "ConnectError" not in str(error)
    assert "https://" not in str(error)
    _assert_unchained(error)


@pytest.mark.parametrize("name", list(HANDLERS))
async def test_unparseable_body_omits_decoder_text(name: str, httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=200, content=b"not-json", is_reusable=True)

    error = await _fetch_identity_error(name)

    with pytest.raises(ValueError) as decoder_error:
        json.loads(b"not-json")
    assert str(decoder_error.value) not in str(error)
    _assert_unchained(error)
