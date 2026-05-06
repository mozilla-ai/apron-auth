from __future__ import annotations

import base64
import json

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.client import OAuthClient
from apron_auth.errors import IdentityFetchError, RevocationError
from apron_auth.models import IdentityProfile, ProviderConfig
from apron_auth.protocols import RevocationHandler
from apron_auth.providers.notion import NotionIdentityHandler, NotionRevocationHandler, maybe_identity_handler, preset

NOTION_REVOKE_URL = "https://api.notion.com/v1/oauth/revoke"
NOTION_ME_URL = "https://api.notion.com/v1/users/me"


class TestNotionIdentityHandler:
    async def test_401_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=NOTION_ME_URL,
            status_code=401,
            json={"object": "error", "message": "unauthorized"},
        )
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        handler = NotionIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Notion identity"):
            await handler.fetch_identity("bad-token", config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=NOTION_ME_URL,
            status_code=200,
            content=b"not-json",
        )
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        handler = NotionIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse Notion identity response"):
            await handler.fetch_identity("access-abc", config)

    async def test_external_user_owned_bot_maps_owner_user_identity(self, httpx_mock: HTTPXMock) -> None:
        payload = {
            "object": "user",
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "Integration Bot",
            "avatar_url": "https://example.com/notion-bot.png",
            "type": "bot",
            "bot": {
                "owner": {
                    "type": "user",
                    "user": {
                        "id": "22222222-2222-2222-2222-222222222222",
                        "name": "Notion Owner",
                        "person": {"email": "owner@example.com"},
                    },
                },
                "workspace_id": "33333333-3333-3333-3333-333333333333",
                "workspace_name": "Example Workspace",
            },
        }
        httpx_mock.add_response(url=NOTION_ME_URL, json=payload)
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        handler = NotionIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity == IdentityProfile(
            subject="22222222-2222-2222-2222-222222222222",
            email="owner@example.com",
            email_verified=None,
            name="Notion Owner",
            username=None,
            avatar_url="https://example.com/notion-bot.png",
            raw=payload,
        )
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers.get("authorization") == "Bearer access-abc"
        assert request.headers.get("notion-version") == "2022-06-28"

    async def test_internal_workspace_owned_bot_returns_workspace_shaped_identity(self, httpx_mock: HTTPXMock) -> None:
        payload = {
            "object": "user",
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "name": "Workspace Integration",
            "avatar_url": "https://example.com/notion-workspace-bot.png",
            "type": "bot",
            "bot": {
                "owner": {"type": "workspace", "workspace": True},
                "workspace_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "workspace_name": "Workspace Alpha",
            },
        }
        httpx_mock.add_response(url=NOTION_ME_URL, json=payload)
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        handler = NotionIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity == IdentityProfile(
            subject="bot:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            email=None,
            email_verified=None,
            name=None,
            username="Workspace Alpha",
            avatar_url="https://example.com/notion-workspace-bot.png",
            raw=payload,
        )


class TestNotionMaybeIdentityHandler:
    def test_canonical_notion_host_returns_handler(self) -> None:
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        handler = maybe_identity_handler(config)
        assert isinstance(handler, NotionIdentityHandler)

    def test_lookalike_host_returns_none(self) -> None:
        config = ProviderConfig(
            client_id="nid",
            client_secret=SecretStr("nsecret"),  # pragma: allowlist secret
            authorize_url="https://api.notion.com.attacker.test/v1/oauth/authorize",
            token_url="https://api.notion.com.attacker.test/v1/oauth/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_authorize_url_matching_returns_none(self) -> None:
        config = ProviderConfig(
            client_id="nid",
            client_secret=SecretStr("nsecret"),  # pragma: allowlist secret
            authorize_url="https://api.notion.com/v1/oauth/authorize",
            token_url="https://attacker.example.com/v1/oauth/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_token_url_matching_returns_none(self) -> None:
        config = ProviderConfig(
            client_id="nid",
            client_secret=SecretStr("nsecret"),  # pragma: allowlist secret
            authorize_url="https://attacker.example.com/v1/oauth/authorize",
            token_url="https://api.notion.com/v1/oauth/token",
        )
        assert maybe_identity_handler(config) is None


class TestNotionPreset:
    def test_config_has_correct_endpoints(self) -> None:
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert config.authorize_url == "https://api.notion.com/v1/oauth/authorize"
        assert config.token_url == "https://api.notion.com/v1/oauth/token"
        assert config.revocation_url == NOTION_REVOKE_URL

    def test_extra_params_include_owner(self) -> None:
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert config.extra_params["owner"] == "user"

    def test_returns_config_and_handler(self) -> None:
        config, handler = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, NotionRevocationHandler)
        assert isinstance(handler, RevocationHandler)

    def test_uses_client_secret_basic(self) -> None:
        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert config.token_endpoint_auth_method == "client_secret_basic"


class TestNotionRevocationHandler:
    @staticmethod
    def _make_config() -> ProviderConfig:
        return ProviderConfig(
            client_id="nid",
            client_secret=SecretStr("nsecret"),
            authorize_url="https://api.notion.com/v1/oauth/authorize",
            token_url="https://api.notion.com/v1/oauth/token",
            revocation_url=NOTION_REVOKE_URL,
            token_endpoint_auth_method="client_secret_basic",
        )

    async def test_already_revoked_returns_true(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=NOTION_REVOKE_URL, status_code=400)
        handler = NotionRevocationHandler()
        result = await handler.revoke("old-token", TestNotionRevocationHandler._make_config())
        assert result is True

    async def test_other_status_returns_false(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=NOTION_REVOKE_URL, status_code=500)
        handler = NotionRevocationHandler()
        result = await handler.revoke("access-token-abc", TestNotionRevocationHandler._make_config())
        assert result is False

    async def test_injected_client_not_closed(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=NOTION_REVOKE_URL, status_code=200)
        client = httpx.AsyncClient()
        handler = NotionRevocationHandler(client=client)
        result = await handler.revoke("access-token-abc", TestNotionRevocationHandler._make_config())
        assert result is True
        assert not client.is_closed
        await client.aclose()

    async def test_network_error_raises_revocation_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        handler = NotionRevocationHandler()
        with pytest.raises(RevocationError, match="Connection refused") as exc_info:
            await handler.revoke("access-token-abc", TestNotionRevocationHandler._make_config())
        assert isinstance(exc_info.value.__cause__, httpx.ConnectError)

    async def test_network_error_with_injected_client(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        client = httpx.AsyncClient()
        handler = NotionRevocationHandler(client=client)
        with pytest.raises(RevocationError, match="Connection refused") as exc_info:
            await handler.revoke("access-token-abc", TestNotionRevocationHandler._make_config())
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

    async def test_successful_revocation(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=NOTION_REVOKE_URL, status_code=200)
        handler = NotionRevocationHandler()
        result = await handler.revoke("access-token-abc", TestNotionRevocationHandler._make_config())
        assert result is True
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.url == NOTION_REVOKE_URL
        assert request.headers["content-type"].startswith("application/json")
        expected = base64.b64encode(b"nid:nsecret").decode()
        assert request.headers["authorization"] == f"Basic {expected}"
        assert json.loads(request.content) == {"token": "access-token-abc"}


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
