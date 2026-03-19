from __future__ import annotations

from pytest_httpx import HTTPXMock

from any_auth.models import ProviderConfig
from any_auth.protocols import RevocationHandler


class TestGitHubPreset:
    def test_returns_config_and_handler(self):
        from any_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from any_auth.providers.github import preset

        config, _ = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        assert config.authorize_url == "https://github.com/login/oauth/authorize"
        assert config.token_url == "https://github.com/login/oauth/access_token"
        assert config.revocation_url == "https://api.github.com/applications/ghid/token"


class TestGitHubRevocationHandler:
    async def test_revokes_via_delete_with_basic_auth(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=204)
        from any_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        result = await handler.revoke("access-abc", config)
        assert result is True
        request = httpx_mock.get_request()
        assert request.method == "DELETE"
        assert request.headers.get("authorization", "").startswith("Basic ")
