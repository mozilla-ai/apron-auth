from __future__ import annotations

import base64
import json

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.client import OAuthClient
from apron_auth.errors import RevocationError
from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler
from apron_auth.providers.notion import NotionRevocationHandler, preset

NOTION_REVOKE_URL = "https://api.notion.com/v1/oauth/revoke"


class TestNotionPreset:
    def test_returns_config_and_handler(self) -> None:
        config, handler = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, NotionRevocationHandler)
        assert isinstance(handler, RevocationHandler)

    def test_uses_client_secret_basic(self) -> None:
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_config_has_correct_endpoints(self) -> None:
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert config.authorize_url == "https://api.notion.com/v1/oauth/authorize"
        assert config.token_url == "https://api.notion.com/v1/oauth/token"
        assert config.revocation_url == NOTION_REVOKE_URL

    def test_extra_params_include_owner(self) -> None:
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert config.extra_params["owner"] == "user"


def _make_config() -> ProviderConfig:
    return ProviderConfig(
        client_id="nid",
        client_secret=SecretStr("nsecret"),
        authorize_url="https://api.notion.com/v1/oauth/authorize",
        token_url="https://api.notion.com/v1/oauth/token",
        revocation_url=NOTION_REVOKE_URL,
        token_endpoint_auth_method="client_secret_basic",
    )


class TestNotionRevocationHandler:
    async def test_successful_revocation(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=NOTION_REVOKE_URL, status_code=200)
        handler = NotionRevocationHandler()
        result = await handler.revoke("access-token-abc", _make_config())
        assert result is True
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.url == NOTION_REVOKE_URL
        assert request.headers["content-type"].startswith("application/json")
        expected = base64.b64encode(b"nid:nsecret").decode()
        assert request.headers["authorization"] == f"Basic {expected}"
        assert json.loads(request.content) == {"token": "access-token-abc"}

    async def test_already_revoked_returns_true(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=NOTION_REVOKE_URL, status_code=400)
        handler = NotionRevocationHandler()
        result = await handler.revoke("old-token", _make_config())
        assert result is True

    async def test_other_status_returns_false(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=NOTION_REVOKE_URL, status_code=500)
        handler = NotionRevocationHandler()
        result = await handler.revoke("access-token-abc", _make_config())
        assert result is False

    async def test_injected_client_not_closed(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=NOTION_REVOKE_URL, status_code=200)
        client = httpx.AsyncClient()
        handler = NotionRevocationHandler(client=client)
        result = await handler.revoke("access-token-abc", _make_config())
        assert result is True
        assert not client.is_closed
        await client.aclose()

    async def test_network_error_raises_revocation_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        handler = NotionRevocationHandler()
        with pytest.raises(RevocationError, match="Connection refused") as exc_info:
            await handler.revoke("access-token-abc", _make_config())
        assert isinstance(exc_info.value.__cause__, httpx.ConnectError)

    async def test_network_error_with_injected_client(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        client = httpx.AsyncClient()
        handler = NotionRevocationHandler(client=client)
        with pytest.raises(RevocationError, match="Connection refused") as exc_info:
            await handler.revoke("access-token-abc", _make_config())
        assert isinstance(exc_info.value.__cause__, httpx.ConnectError)
        assert not client.is_closed
        await client.aclose()

    async def test_raises_when_revocation_url_missing(self) -> None:
        config = ProviderConfig(
            client_id="nid",
            client_secret=SecretStr("nsecret"),
            authorize_url="https://api.notion.com/v1/oauth/authorize",
            token_url="https://api.notion.com/v1/oauth/token",
            token_endpoint_auth_method="client_secret_basic",
        )
        handler = NotionRevocationHandler()
        with pytest.raises(ValueError, match="revocation_url"):
            await handler.revoke("access-token-abc", config)


class TestNotionRevocationViaOAuthClient:
    async def test_revoke_token_succeeds_with_preset(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=NOTION_REVOKE_URL, status_code=200)
        config, handler = preset(client_id="nid", client_secret="nsecret", scopes=[])
        client = OAuthClient(config=config, revocation_handler=handler)
        result = await client.revoke_token("access-token-abc")
        assert result is True

        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.url == NOTION_REVOKE_URL
