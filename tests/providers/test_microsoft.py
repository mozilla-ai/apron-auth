from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig


class TestMicrosoftPreset:
    def test_returns_config_and_none_handler(self):
        from apron_auth.providers.microsoft import preset

        config, handler = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert isinstance(config, ProviderConfig)
        assert handler is None

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.microsoft import preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert config.authorize_url == "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        assert config.token_url == "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        assert config.revocation_url is None

    def test_extra_params_include_prompt(self):
        from apron_auth.providers.microsoft import preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert config.extra_params["prompt"] == "consent"

    def test_base_scopes_merged_with_caller_scopes(self):
        from apron_auth.providers.microsoft import BASE_SCOPES, preset

        config, _ = preset(
            client_id="mid",
            client_secret="msecret",  # pragma: allowlist secret
            scopes=["Mail.Read"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "Mail.Read" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        from apron_auth.providers.microsoft import preset

        config, _ = preset(
            client_id="mid",
            client_secret="msecret",  # pragma: allowlist secret
            scopes=["offline_access", "Mail.Read"],
        )
        assert config.scopes.count("offline_access") == 1

    def test_scope_metadata_covers_base_scopes(self):
        from apron_auth.providers.microsoft import BASE_SCOPES, preset

        config, _ = preset(
            client_id="mid",
            client_secret="msecret",  # pragma: allowlist secret
            scopes=["Mail.Read"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)


class TestMicrosoftIdentityHandler:
    async def test_happy_path_returns_identity_profile(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://graph.microsoft.com/oidc/userinfo",
            json={
                "sub": "ms-user-123",
                "email": "user@example.com",
                "name": "Test User",
                "picture": "https://example.com/avatar.png",
            },
        )
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler, preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["openid"])
        handler = MicrosoftIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity == IdentityProfile(
            subject="ms-user-123",
            email="user@example.com",
            email_verified=None,
            name="Test User",
            avatar_url="https://example.com/avatar.png",
            raw={
                "sub": "ms-user-123",
                "email": "user@example.com",
                "name": "Test User",
                "picture": "https://example.com/avatar.png",
            },
        )
        request = httpx_mock.get_request()
        assert request.headers.get("authorization") == "Bearer access-abc"

    async def test_401_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://graph.microsoft.com/oidc/userinfo",
            status_code=401,
            json={"error": "invalid_token"},
        )
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler, preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["openid"])
        handler = MicrosoftIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Microsoft identity"):
            await handler.fetch_identity("bad-token", config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://graph.microsoft.com/oidc/userinfo",
            status_code=200,
            content=b"not-json",
        )
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler, preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["openid"])
        handler = MicrosoftIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse Microsoft identity response"):
            await handler.fetch_identity("access-abc", config)


class TestMicrosoftMaybeIdentityHandler:
    def test_canonical_microsoft_host_returns_handler(self):
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler, maybe_identity_handler, preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["openid"])
        handler = maybe_identity_handler(config)
        assert isinstance(handler, MicrosoftIdentityHandler)

    def test_lookalike_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.microsoft import maybe_identity_handler

        config = ProviderConfig(
            client_id="mid",
            client_secret=SecretStr("msecret"),  # pragma: allowlist secret
            authorize_url="https://evilmicrosoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://evilmicrosoftonline.com/common/oauth2/v2.0/token",
        )
        assert maybe_identity_handler(config) is None

    def test_non_microsoft_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.microsoft import maybe_identity_handler

        config = ProviderConfig(
            client_id="mid",
            client_secret=SecretStr("msecret"),  # pragma: allowlist secret
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
        )
        assert maybe_identity_handler(config) is None
