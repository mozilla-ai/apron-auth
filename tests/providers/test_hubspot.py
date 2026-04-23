from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.client import OAuthClient
from apron_auth.errors import RevocationError
from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler


class TestHubSpotPreset:
    def test_returns_config_and_handler(self):
        from apron_auth.providers.hubspot import preset

        config, handler = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.hubspot import preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        assert config.authorize_url == "https://app.hubspot.com/oauth/authorize"
        assert config.token_url == "https://api.hubapi.com/oauth/v1/token"
        assert config.revocation_url == "https://api.hubapi.com/oauth/v1/refresh-tokens"

    def test_token_endpoint_auth_method_is_client_secret_post(self):
        from apron_auth.providers.hubspot import preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        assert config.token_endpoint_auth_method == "client_secret_post"

    def test_extra_params_passed_through(self):
        from apron_auth.providers.hubspot import preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
            extra_params={"optional_scope": "sales"},
        )
        assert config.extra_params == {"optional_scope": "sales"}


class TestHubSpotRevocationHandler:
    async def test_revokes_refresh_token_via_delete(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.hubspot import preset

        config, handler = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        result = await handler.revoke("refresh-abc", config)
        assert result is True

        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "DELETE"
        assert str(request.url) == "https://api.hubapi.com/oauth/v1/refresh-tokens/refresh-abc"

    async def test_404_treated_as_success(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=404)
        from apron_auth.providers.hubspot import preset

        config, handler = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        result = await handler.revoke("refresh-missing", config)
        assert result is True

    async def test_non_success_status_returns_false(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=500)
        from apron_auth.providers.hubspot import preset

        config, handler = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        result = await handler.revoke("refresh-abc", config)
        assert result is False

    async def test_url_encodes_path_significant_chars(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.hubspot import preset

        config, handler = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        raw_token = "a/b+c=d e"
        result = await handler.revoke(raw_token, config)
        assert result is True

        request = httpx_mock.get_request()
        assert request is not None
        expected = "https://api.hubapi.com/oauth/v1/refresh-tokens/a%2Fb%2Bc%3Dd%20e"
        assert str(request.url) == expected

    async def test_network_error_raises_revocation_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        from apron_auth.providers.hubspot import preset

        config, handler = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        with pytest.raises(RevocationError, match="Connection refused") as exc_info:
            await handler.revoke("refresh-abc", config)
        assert isinstance(exc_info.value.__cause__, httpx.ConnectError)

    async def test_accepts_injected_client(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.hubspot import HubSpotRevocationHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        client = httpx.AsyncClient()
        handler = HubSpotRevocationHandler(client=client)
        result = await handler.revoke("refresh-abc", config)
        assert result is True
        assert not client.is_closed
        await client.aclose()

    async def test_raises_when_revocation_url_missing(self):
        from apron_auth.providers.hubspot import HubSpotRevocationHandler

        config = ProviderConfig(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            authorize_url="https://app.hubspot.com/oauth/authorize",
            token_url="https://api.hubapi.com/oauth/v1/token",
            scopes=["contacts"],
        )
        handler = HubSpotRevocationHandler()
        with pytest.raises(ValueError, match="revocation_url"):
            await handler.revoke("refresh-abc", config)


class TestHubSpotRevocationViaOAuthClient:
    async def test_revoke_token_succeeds_with_preset(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.hubspot import preset

        config, handler = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        client = OAuthClient(config=config, revocation_handler=handler)
        result = await client.revoke_token("refresh-abc")
        assert result is True

        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "DELETE"
        assert str(request.url) == "https://api.hubapi.com/oauth/v1/refresh-tokens/refresh-abc"
