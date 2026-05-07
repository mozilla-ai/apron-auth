from __future__ import annotations

from pytest_httpx import HTTPXMock

from apron_auth.models import ProviderConfig, TenancyContext
from apron_auth.protocols import RevocationHandler

GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


class TestGoogleIdentityHandler:
    async def test_workspace_account_populates_domain_only(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "email": "user@mozilla.ai", "hd": "mozilla.ai"},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config, _ = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.tenancies == (TenancyContext(domain="mozilla.ai"),)

    async def test_consumer_account_yields_empty_tenancies(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "email": "user@gmail.com"},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config, _ = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.tenancies == ()

    async def test_empty_string_hd_yields_empty_tenancies(self, httpx_mock: HTTPXMock):
        """A pathologically-shaped response with ``hd=""`` must not
        emit a TenancyContext with ``domain=""`` — guard explicitly."""
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "hd": ""},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config, _ = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.tenancies == ()


class TestGoogleMaybeIdentityHandler:
    def test_canonical_google_host_returns_handler(self):
        from apron_auth.providers.google import GoogleIdentityHandler, maybe_identity_handler, preset

        config, _ = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = maybe_identity_handler(config)
        assert isinstance(handler, GoogleIdentityHandler)

    def test_lookalike_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.google import maybe_identity_handler

        config = ProviderConfig(
            client_id="gid",
            client_secret=SecretStr("gsecret"),  # pragma: allowlist secret
            authorize_url="https://evilgoogle.com/o/oauth2/v2/auth",
            token_url="https://evilgoogle.com/token",
        )
        assert maybe_identity_handler(config) is None

    def test_non_google_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.google import maybe_identity_handler

        config = ProviderConfig(
            client_id="gid",
            client_secret=SecretStr("gsecret"),  # pragma: allowlist secret
            authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_authorize_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.google import maybe_identity_handler

        config = ProviderConfig(
            client_id="gid",
            client_secret=SecretStr("gsecret"),  # pragma: allowlist secret
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://attacker.example.com/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_token_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.google import maybe_identity_handler

        config = ProviderConfig(
            client_id="gid",
            client_secret=SecretStr("gsecret"),  # pragma: allowlist secret
            authorize_url="https://attacker.example.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
        )
        assert maybe_identity_handler(config) is None


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
