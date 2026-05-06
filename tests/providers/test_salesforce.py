from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig
from apron_auth.protocols import RevocationHandler
from apron_auth.providers.salesforce import BASE_SCOPES, preset


class TestSalesforcePreset:
    def test_returns_config_and_handler(self):
        config, handler = preset(client_id="sfid", client_secret="sfsecret", scopes=["api"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        config, _ = preset(client_id="sfid", client_secret="sfsecret", scopes=["api"])
        assert config.authorize_url == "https://login.salesforce.com/services/oauth2/authorize"
        assert config.token_url == "https://login.salesforce.com/services/oauth2/token"
        assert config.revocation_url == "https://login.salesforce.com/services/oauth2/revoke"

    def test_sandbox_host_produces_test_endpoints(self):
        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["api"],
            host="test.salesforce.com",
        )
        assert config.authorize_url == "https://test.salesforce.com/services/oauth2/authorize"
        assert config.token_url == "https://test.salesforce.com/services/oauth2/token"
        assert config.revocation_url == "https://test.salesforce.com/services/oauth2/revoke"

    @pytest.mark.parametrize(
        "bad_host",
        [
            "",
            "https://test.salesforce.com",
            "http://test.salesforce.com",
            "test.salesforce.com/",
            "test.salesforce.com/services/oauth2/authorize",
            "test.salesforce.com?foo=bar",
            "test.salesforce.com#frag",
            "user@test.salesforce.com",
            "test.salesforce.com ",
            "test .salesforce.com",
        ],
    )
    def test_malformed_host_raises_value_error(self, bad_host: str):
        with pytest.raises(ValueError, match="bare hostname"):
            preset(
                client_id="sfid",
                client_secret="sfsecret",  # pragma: allowlist secret
                scopes=["api"],
                host=bad_host,
            )

    def test_base_scopes_merged_with_caller_scopes(self):
        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["api"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "api" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["refresh_token", "api"],
        )
        assert config.scopes.count("refresh_token") == 1

    def test_scope_metadata_covers_base_scopes(self):
        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["api"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)


class TestSalesforceIdentityHandler:
    async def test_happy_path_returns_identity_profile(self, httpx_mock: HTTPXMock):
        payload = {
            "sub": "https://login.salesforce.com/id/00Dxx0000001gZWEAY/005xx000001SwiUAAS",
            "email": "user@example.com",
            "email_verified": True,
            "name": "Test User",
            "nickname": "tuser",
            "preferred_username": "user@example.com.dev",
            "picture": "https://example.com/avatar.png",
            "user_id": "005xx000001SwiUAAS",
            "organization_id": "00Dxx0000001gZWEAY",
            "urls": {
                "rest": "https://acme.my.salesforce.com/services/data/v{version}/",
                "sobjects": "https://acme.my.salesforce.com/services/data/v{version}/sobjects/",
            },
        }
        httpx_mock.add_response(url="https://login.salesforce.com/services/oauth2/userinfo", json=payload)
        from apron_auth.providers.salesforce import SalesforceIdentityHandler

        config, _ = preset(client_id="sfid", client_secret="sfsecret", scopes=["openid"])
        handler = SalesforceIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity == IdentityProfile(
            subject="https://login.salesforce.com/id/00Dxx0000001gZWEAY/005xx000001SwiUAAS",
            email="user@example.com",
            email_verified=True,
            name="Test User",
            username="tuser",
            avatar_url="https://example.com/avatar.png",
            raw=payload,
        )
        request = httpx_mock.get_request()
        assert request.headers.get("authorization") == "Bearer access-abc"

    async def test_username_falls_back_to_preferred_username(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://login.salesforce.com/services/oauth2/userinfo",
            json={
                "sub": "https://login.salesforce.com/id/X/Y",
                "preferred_username": "user@example.com.dev",
            },
        )
        from apron_auth.providers.salesforce import SalesforceIdentityHandler

        config, _ = preset(client_id="sfid", client_secret="sfsecret", scopes=["openid"])
        handler = SalesforceIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.username == "user@example.com.dev"

    async def test_sandbox_host_drives_userinfo_url(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://test.salesforce.com/services/oauth2/userinfo",
            json={"sub": "https://test.salesforce.com/id/X/Y", "email": "sandbox@example.com"},
        )
        from apron_auth.providers.salesforce import SalesforceIdentityHandler

        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["openid"],
            host="test.salesforce.com",
        )
        handler = SalesforceIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.email == "sandbox@example.com"

    async def test_my_domain_host_drives_userinfo_url(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://acme.my.salesforce.com/services/oauth2/userinfo",
            json={"sub": "https://acme.my.salesforce.com/id/X/Y", "email": "mydomain@example.com"},
        )
        from apron_auth.providers.salesforce import SalesforceIdentityHandler

        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["openid"],
            host="acme.my.salesforce.com",
        )
        handler = SalesforceIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.email == "mydomain@example.com"

    async def test_401_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://login.salesforce.com/services/oauth2/userinfo",
            status_code=401,
            json={"error": "invalid_token"},
        )
        from apron_auth.providers.salesforce import SalesforceIdentityHandler

        config, _ = preset(client_id="sfid", client_secret="sfsecret", scopes=["openid"])
        handler = SalesforceIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Salesforce identity"):
            await handler.fetch_identity("bad-token", config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://login.salesforce.com/services/oauth2/userinfo",
            status_code=200,
            content=b"not-json",
        )
        from apron_auth.providers.salesforce import SalesforceIdentityHandler

        config, _ = preset(client_id="sfid", client_secret="sfsecret", scopes=["openid"])
        handler = SalesforceIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse Salesforce identity response"):
            await handler.fetch_identity("access-abc", config)


class TestSalesforceMaybeIdentityHandler:
    def test_canonical_login_host_returns_handler(self):
        from apron_auth.providers.salesforce import SalesforceIdentityHandler, maybe_identity_handler

        config, _ = preset(client_id="sfid", client_secret="sfsecret", scopes=["openid"])
        handler = maybe_identity_handler(config)
        assert isinstance(handler, SalesforceIdentityHandler)

    def test_sandbox_host_returns_handler(self):
        from apron_auth.providers.salesforce import SalesforceIdentityHandler, maybe_identity_handler

        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["openid"],
            host="test.salesforce.com",
        )
        handler = maybe_identity_handler(config)
        assert isinstance(handler, SalesforceIdentityHandler)

    def test_my_domain_host_returns_handler(self):
        from apron_auth.providers.salesforce import SalesforceIdentityHandler, maybe_identity_handler

        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["openid"],
            host="acme.my.salesforce.com",
        )
        handler = maybe_identity_handler(config)
        assert isinstance(handler, SalesforceIdentityHandler)

    def test_lookalike_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.salesforce import maybe_identity_handler

        config = ProviderConfig(
            client_id="sfid",
            client_secret=SecretStr("sfsecret"),  # pragma: allowlist secret
            authorize_url="https://evilsalesforce.com/services/oauth2/authorize",
            token_url="https://evilsalesforce.com/services/oauth2/token",
        )
        assert maybe_identity_handler(config) is None

    def test_non_salesforce_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.salesforce import maybe_identity_handler

        config = ProviderConfig(
            client_id="sfid",
            client_secret=SecretStr("sfsecret"),  # pragma: allowlist secret
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
        )
        assert maybe_identity_handler(config) is None
