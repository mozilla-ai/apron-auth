from __future__ import annotations

from pytest_httpx import HTTPXMock

from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler


class TestSlackPreset:
    def test_returns_config_and_handler(self):
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        assert config.authorize_url == "https://slack.com/oauth/v2/authorize"
        assert config.token_url == "https://slack.com/api/oauth.v2.access"
        assert config.revocation_url == "https://slack.com/api/auth.revoke"

    def test_scope_separator_is_comma(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read", "chat:write"])
        assert config.scope_separator == ","


class TestSlackRevocationHandler:
    async def test_revokes_via_get(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(json={"ok": True, "revoked": True})
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        result = await handler.revoke("access-abc", config)
        assert result is True
        request = httpx_mock.get_request()
        assert request.method == "GET"
        assert "token=access-abc" in str(request.url)
