from __future__ import annotations

import traceback

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.client import OAuthClient
from apron_auth.errors import IdentityFetchError, RevocationError
from apron_auth.models import IdentityProfile, ProviderConfig, TenancyContext
from apron_auth.protocols import RevocationHandler


class TestHubSpotIdentityHandler:
    async def test_4xx_does_not_leak_access_token_in_error_message(self, httpx_mock: HTTPXMock):
        secret = "secret-access-token-DO-NOT-LEAK"  # pragma: allowlist secret
        httpx_mock.add_response(
            url=f"https://api.hubapi.com/oauth/v1/access-tokens/{secret}",
            status_code=401,
            json={"error": "invalid_token"},
        )
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = HubSpotIdentityHandler()

        with pytest.raises(IdentityFetchError) as exc_info:
            await handler.fetch_identity(secret, config)
        assert secret not in str(exc_info.value)
        assert secret not in repr(exc_info.value)
        assert "401" in str(exc_info.value)
        formatted = "".join(traceback.format_exception(exc_info.value))
        assert secret not in formatted
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__ is True

    async def test_happy_path_returns_identity_profile(self, httpx_mock: HTTPXMock):
        payload = {
            "user_id": 1234567,
            "user": "user@example.com",
            "hub_id": 7654321,
            "hub_domain": "acme.example.com",
            "app_id": 999,
            "scopes": ["contacts", "oauth"],
            "token_type": "access",
            "expires_in": 21600,
        }
        httpx_mock.add_response(
            url="https://api.hubapi.com/oauth/v1/access-tokens/access-abc",
            json=payload,
        )
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = HubSpotIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity == IdentityProfile(
            subject="1234567",
            email="user@example.com",
            email_verified=None,
            name=None,
            username=None,
            avatar_url=None,
            tenancies=(TenancyContext(id="7654321", domain="acme.example.com"),),
            raw=payload,
        )

    async def test_username_is_none_when_hub_domain_present(self, httpx_mock: HTTPXMock):
        """Regression guard: hub_domain belongs in TenancyContext.domain,
        not IdentityProfile.username (former workaround removed)."""
        payload = {
            "user_id": 1,
            "user": "u@example.com",
            "hub_id": 42,
            "hub_domain": "acme.example.com",
        }
        httpx_mock.add_response(
            url="https://api.hubapi.com/oauth/v1/access-tokens/access-abc",
            json=payload,
        )
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = HubSpotIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.username is None
        assert identity.tenancies[0].domain == "acme.example.com"

    async def test_no_hub_id_yields_empty_tenancies(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.hubapi.com/oauth/v1/access-tokens/access-abc",
            json={"user_id": 1, "user": "u@example.com"},
        )
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = HubSpotIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.tenancies == ()

    async def test_hub_id_present_but_hub_domain_missing(self, httpx_mock: HTTPXMock):
        """``hub_id`` is the canonical anchor; emit the tenancy with
        ``domain=None`` when ``hub_domain`` is unexpectedly absent
        rather than silently dropping the portal binding."""
        httpx_mock.add_response(
            url="https://api.hubapi.com/oauth/v1/access-tokens/access-abc",
            json={"user_id": 1, "user": "u@example.com", "hub_id": 42},
        )
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = HubSpotIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.tenancies == (TenancyContext(id="42", domain=None),)

    async def test_network_error_does_not_leak_access_token_in_error_message(self, httpx_mock: HTTPXMock):
        secret = "secret-access-token-DO-NOT-LEAK"  # pragma: allowlist secret
        httpx_mock.add_exception(
            httpx.ConnectError(
                f"Connection refused to https://api.hubapi.com/oauth/v1/access-tokens/{secret}",
            ),
        )
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = HubSpotIdentityHandler()

        with pytest.raises(IdentityFetchError) as exc_info:
            await handler.fetch_identity(secret, config)
        assert secret not in str(exc_info.value)
        assert secret not in repr(exc_info.value)
        formatted = "".join(traceback.format_exception(exc_info.value))
        assert secret not in formatted
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__ is True
        assert "ConnectError" in str(exc_info.value)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.hubapi.com/oauth/v1/access-tokens/access-abc",
            status_code=200,
            content=b"not-json",
        )
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = HubSpotIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse HubSpot identity response"):
            await handler.fetch_identity("access-abc", config)

    async def test_subject_is_none_when_user_id_missing(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.hubapi.com/oauth/v1/access-tokens/access-abc",
            json={"user": "user@example.com", "hub_id": 42, "hub_domain": "acme.example.com"},
        )
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = HubSpotIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.subject is None
        assert identity.email == "user@example.com"
        assert identity.username is None
        assert identity.tenancies[0].domain == "acme.example.com"

    async def test_url_encodes_path_significant_chars_in_token(self, httpx_mock: HTTPXMock):
        raw_token = "a/b+c=d e"
        encoded_path = "a%2Fb%2Bc%3Dd%20e"
        httpx_mock.add_response(
            url=f"https://api.hubapi.com/oauth/v1/access-tokens/{encoded_path}",
            json={"user_id": 1, "user": "u@example.com", "hub_domain": "acme.example.com"},
        )
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = HubSpotIdentityHandler()

        identity = await handler.fetch_identity(raw_token, config)
        assert identity.email == "u@example.com"


class TestHubSpotMaybeIdentityHandler:
    def test_canonical_hubspot_hosts_returns_handler(self):
        from apron_auth.providers.hubspot import HubSpotIdentityHandler, maybe_identity_handler, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        handler = maybe_identity_handler(config)
        assert isinstance(handler, HubSpotIdentityHandler)

    def test_lookalike_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.hubspot import maybe_identity_handler

        config = ProviderConfig(
            client_id="hsid",
            client_secret=SecretStr("hssecret"),  # pragma: allowlist secret
            authorize_url="https://evilhubspot.com/oauth/authorize",
            token_url="https://evilhubapi.com/oauth/v1/token",
        )
        assert maybe_identity_handler(config) is None

    def test_non_hubspot_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.hubspot import maybe_identity_handler

        config = ProviderConfig(
            client_id="hsid",
            client_secret=SecretStr("hssecret"),  # pragma: allowlist secret
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_authorize_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.hubspot import maybe_identity_handler

        config = ProviderConfig(
            client_id="hsid",
            client_secret=SecretStr("hssecret"),  # pragma: allowlist secret
            authorize_url="https://app.hubspot.com/oauth/authorize",
            token_url="https://attacker.example.com/oauth/v1/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_token_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.hubspot import maybe_identity_handler

        config = ProviderConfig(
            client_id="hsid",
            client_secret=SecretStr("hssecret"),  # pragma: allowlist secret
            authorize_url="https://attacker.example.com/oauth/authorize",
            token_url="https://api.hubapi.com/oauth/v1/token",
        )
        assert maybe_identity_handler(config) is None


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

    def test_base_scopes_merged_with_caller_scopes(self):
        from apron_auth.providers.hubspot import BASE_SCOPES, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "contacts" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        from apron_auth.providers.hubspot import preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["oauth", "contacts"],
        )
        assert config.scopes.count("oauth") == 1

    def test_scope_metadata_covers_base_scopes(self):
        from apron_auth.providers.hubspot import BASE_SCOPES, preset

        config, _ = preset(
            client_id="hsid",
            client_secret="hssecret",  # pragma: allowlist secret
            scopes=["contacts"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)


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
