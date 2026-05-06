from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig
from apron_auth.protocols import RevocationHandler


class TestAtlassianPreset:
    def test_returns_config_and_handler(self):
        from apron_auth.providers.atlassian import preset

        config, handler = preset(client_id="aid", client_secret="asecret", scopes=["read:jira-work"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.atlassian import preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:jira-work"])
        assert config.authorize_url == "https://auth.atlassian.com/authorize"
        assert config.token_url == "https://auth.atlassian.com/oauth/token"
        assert config.revocation_url == "https://auth.atlassian.com/oauth/revoke"

    def test_extra_params_include_audience(self):
        from apron_auth.providers.atlassian import preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:jira-work"])
        assert config.extra_params["audience"] == "api.atlassian.com"
        assert config.extra_params["prompt"] == "consent"

    def test_base_scopes_merged_with_caller_scopes(self):
        from apron_auth.providers.atlassian import BASE_SCOPES, preset

        config, _ = preset(
            client_id="aid",
            client_secret="asecret",  # pragma: allowlist secret
            scopes=["read:jira-work"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "read:jira-work" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        from apron_auth.providers.atlassian import preset

        config, _ = preset(
            client_id="aid",
            client_secret="asecret",  # pragma: allowlist secret
            scopes=["offline_access", "read:jira-work"],
        )
        assert config.scopes.count("offline_access") == 1

    def test_scope_metadata_covers_base_scopes(self):
        from apron_auth.providers.atlassian import BASE_SCOPES, preset

        config, _ = preset(
            client_id="aid",
            client_secret="asecret",  # pragma: allowlist secret
            scopes=["read:jira-work"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)


class TestAtlassianIdentityHandler:
    async def test_happy_path_returns_identity_profile(self, httpx_mock: HTTPXMock):
        payload = {
            "account_id": "557058:abc-123",
            "email": "user@example.com",
            "name": "Test User",
            "nickname": "tuser",
            "picture": "https://example.com/avatar.png",
            "account_type": "atlassian",
            "account_status": "active",
            "extended_profile": {"job_title": "Engineer"},
            "zoneinfo": "Europe/London",
            "locale": "en-GB",
        }
        httpx_mock.add_response(url="https://api.atlassian.com/me", json=payload)
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity == IdentityProfile(
            subject="557058:abc-123",
            email="user@example.com",
            email_verified=None,
            name="Test User",
            username="tuser",
            avatar_url="https://example.com/avatar.png",
            raw=payload,
        )
        request = httpx_mock.get_request()
        assert request.headers.get("authorization") == "Bearer access-abc"

    async def test_401_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.atlassian.com/me",
            status_code=401,
            json={"error": "invalid_token"},
        )
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Atlassian identity"):
            await handler.fetch_identity("bad-token", config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.atlassian.com/me",
            status_code=200,
            content=b"not-json",
        )
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse Atlassian identity response"):
            await handler.fetch_identity("access-abc", config)


class TestAtlassianMaybeIdentityHandler:
    def test_canonical_atlassian_host_returns_handler(self):
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, maybe_identity_handler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = maybe_identity_handler(config)
        assert isinstance(handler, AtlassianIdentityHandler)

    def test_lookalike_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.atlassian import maybe_identity_handler

        config = ProviderConfig(
            client_id="aid",
            client_secret=SecretStr("asecret"),  # pragma: allowlist secret
            authorize_url="https://evilauth.atlassian.com.attacker.test/authorize",
            token_url="https://evilauth.atlassian.com.attacker.test/oauth/token",
        )
        assert maybe_identity_handler(config) is None

    def test_non_atlassian_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.atlassian import maybe_identity_handler

        config = ProviderConfig(
            client_id="aid",
            client_secret=SecretStr("asecret"),  # pragma: allowlist secret
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_authorize_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.atlassian import maybe_identity_handler

        config = ProviderConfig(
            client_id="aid",
            client_secret=SecretStr("asecret"),  # pragma: allowlist secret
            authorize_url="https://auth.atlassian.com/authorize",
            token_url="https://attacker.example.com/oauth/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_token_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.atlassian import maybe_identity_handler

        config = ProviderConfig(
            client_id="aid",
            client_secret=SecretStr("asecret"),  # pragma: allowlist secret
            authorize_url="https://attacker.example.com/authorize",
            token_url="https://auth.atlassian.com/oauth/token",
        )
        assert maybe_identity_handler(config) is None
