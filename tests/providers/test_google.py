from __future__ import annotations

from pytest_httpx import HTTPXMock

from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler


class TestGooglePreset:
    def test_returns_config_and_handler(self):
        from apron_auth.providers.google import preset

        config, handler = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        assert isinstance(config, ProviderConfig)
        assert handler is not None
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.google import preset

        config, _ = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        assert config.authorize_url == "https://accounts.google.com/o/oauth2/v2/auth"
        assert config.token_url == "https://oauth2.googleapis.com/token"
        assert config.revocation_url == "https://oauth2.googleapis.com/revoke"

    def test_extra_params_include_offline_access(self):
        from apron_auth.providers.google import preset

        config, _ = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        assert config.extra_params["access_type"] == "offline"
        assert config.extra_params["prompt"] == "consent"

    def test_extra_params_can_be_overridden(self):
        from apron_auth.providers.google import preset

        config, _ = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["openid"],
            extra_params={"prompt": "select_account"},
        )
        assert config.extra_params["prompt"] == "select_account"
        assert config.extra_params["access_type"] == "offline"

    def test_redirect_uri_override(self):
        from apron_auth.providers.google import preset

        config, _ = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["openid"],
            redirect_uri="https://custom.example.com/callback",
        )
        assert config.redirect_uri == "https://custom.example.com/callback"

    def test_base_scopes_merged_with_caller_scopes(self):
        from apron_auth.providers.google import BASE_SCOPES, preset

        config, _ = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "https://www.googleapis.com/auth/gmail.readonly" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        from apron_auth.providers.google import preset

        config, _ = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["openid", "https://www.googleapis.com/auth/gmail.readonly"],
        )
        assert config.scopes.count("openid") == 1

    def test_scope_metadata_covers_base_scopes(self):
        from apron_auth.providers.google import BASE_SCOPES, preset

        config, _ = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)


class TestGoogleRevocationHandler:
    async def test_revokes_via_post_with_query_param(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=200)
        from apron_auth.providers.google import preset

        config, handler = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        result = await handler.revoke("access-abc", config)
        assert result is True
        request = httpx_mock.get_request()
        assert request.method == "POST"
        assert "token=access-abc" in str(request.url)
