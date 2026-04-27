from __future__ import annotations

import json

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import RevocationError
from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler


class TestGitHubPreset:
    def test_returns_config_and_handler(self):
        from apron_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.github import preset

        config, _ = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        assert config.authorize_url == "https://github.com/login/oauth/authorize"
        assert config.token_url == "https://github.com/login/oauth/access_token"
        assert config.revocation_url == "https://api.github.com/applications/ghid/grant"

    def test_base_scopes_merged_with_caller_scopes(self):
        from apron_auth.providers.github import BASE_SCOPES, preset

        config, _ = preset(
            client_id="ghid",
            client_secret="ghsecret",  # pragma: allowlist secret
            scopes=["repo"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "repo" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        from apron_auth.providers.github import preset

        config, _ = preset(
            client_id="ghid",
            client_secret="ghsecret",  # pragma: allowlist secret
            scopes=["read:user", "repo"],
        )
        assert config.scopes.count("read:user") == 1

    def test_scope_metadata_covers_base_scopes(self):
        from apron_auth.providers.github import BASE_SCOPES, preset

        config, _ = preset(
            client_id="ghid",
            client_secret="ghsecret",  # pragma: allowlist secret
            scopes=["repo"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)


class TestGitHubRevocationHandler:
    async def test_revokes_via_delete_with_basic_auth(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        result = await handler.revoke("access-abc", config)
        assert result is True
        request = httpx_mock.get_request()
        assert request.method == "DELETE"
        assert request.headers.get("authorization", "").startswith("Basic ")

    async def test_sends_github_api_headers(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        await handler.revoke("access-abc", config)
        request = httpx_mock.get_request()
        assert request.headers.get("accept") == "application/vnd.github+json"
        assert request.headers.get("x-github-api-version") == "2022-11-28"

    async def test_sends_access_token_in_body(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        await handler.revoke("access-abc", config)
        request = httpx_mock.get_request()
        payload = json.loads(request.content)
        assert payload == {"access_token": "access-abc"}

    async def test_not_found_is_idempotent_success(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=404)
        from apron_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        result = await handler.revoke("access-abc", config)
        assert result is True

    async def test_validation_failure_returns_false(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=422)
        from apron_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        result = await handler.revoke("access-abc", config)
        assert result is False

    async def test_unexpected_status_returns_false(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=500)
        from apron_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        result = await handler.revoke("access-abc", config)
        assert result is False

    async def test_successful_revocation_with_injected_client(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.github import GitHubRevocationHandler, preset

        config, _ = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        client = httpx.AsyncClient()
        handler = GitHubRevocationHandler(client=client)
        result = await handler.revoke("access-abc", config)
        assert result is True
        assert not client.is_closed
        await client.aclose()

    async def test_network_error_raises_revocation_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        from apron_auth.providers.github import preset

        config, handler = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        with pytest.raises(RevocationError, match="Connection refused") as exc_info:
            await handler.revoke("access-abc", config)
        assert isinstance(exc_info.value.__cause__, httpx.ConnectError)

    async def test_network_error_with_injected_client_keeps_client_open(self, httpx_mock: HTTPXMock):
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        from apron_auth.providers.github import GitHubRevocationHandler, preset

        config, _ = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        client = httpx.AsyncClient()
        handler = GitHubRevocationHandler(client=client)
        with pytest.raises(RevocationError, match="Connection refused"):
            await handler.revoke("access-abc", config)
        assert not client.is_closed
        await client.aclose()
