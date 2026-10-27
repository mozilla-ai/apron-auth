from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityMaterial, IdentityProfile, ProviderConfig, TenancyContext
from apron_auth.protocols import RevocationHandler
from apron_auth.providers import revocation_handler_for
from apron_auth.providers.linear import LinearIdentityHandler, preset

LINEAR_GRAPHQL_URL = "https://api.linear.app/graphql"


class TestLinearIdentityHandler:
    async def test_happy_path_maps_viewer_fields(self, httpx_mock: HTTPXMock) -> None:
        viewer = {
            "id": "user-123",
            "name": "Linear User",
            "displayName": "luser",
            "email": "user@example.com",
            "avatarUrl": "https://example.com/avatar.png",
        }
        organization = {"id": "org-1", "name": "Acme", "urlKey": "acme"}
        httpx_mock.add_response(
            url=LINEAR_GRAPHQL_URL,
            json={"data": {"viewer": viewer, "organization": organization}},
        )
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity == IdentityProfile(
            provider="linear",
            subject="user-123",
            email="user@example.com",
            email_verified=None,
            name="Linear User",
            username="luser",
            avatar_url="https://example.com/avatar.png",
            tenancies=(TenancyContext(id="org-1", name="Acme", domain="acme", raw=organization),),
            raw=viewer,
        )
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.headers.get("authorization") == "Bearer access-abc"
        assert request.headers["content-type"].startswith("application/json")

    async def test_missing_organization_yields_empty_tenancies(self, httpx_mock: HTTPXMock) -> None:
        """Tokens issued before the GraphQL extension landed return only
        ``viewer`` — the handler must degrade to ``tenancies=()``."""
        viewer = {"id": "user-123", "email": "user@example.com"}
        httpx_mock.add_response(url=LINEAR_GRAPHQL_URL, json={"data": {"viewer": viewer}})
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.tenancies == ()

    async def test_organization_without_id_yields_empty_tenancies(self, httpx_mock: HTTPXMock) -> None:
        """``organization.id`` is the canonical anchor; without it we
        cannot key the tenancy and degrade to ``tenancies=()``."""
        viewer = {"id": "user-123"}
        organization = {"name": "Acme", "urlKey": "acme"}
        httpx_mock.add_response(
            url=LINEAR_GRAPHQL_URL,
            json={"data": {"viewer": viewer, "organization": organization}},
        )
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.tenancies == ()

    async def test_organization_id_present_but_name_and_url_key_missing(self, httpx_mock: HTTPXMock) -> None:
        viewer = {"id": "user-123"}
        organization = {"id": "org-1"}
        httpx_mock.add_response(
            url=LINEAR_GRAPHQL_URL,
            json={"data": {"viewer": viewer, "organization": organization}},
        )
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.tenancies == (TenancyContext(id="org-1", name=None, domain=None, raw=organization),)

    async def test_graphql_errors_in_200_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=LINEAR_GRAPHQL_URL,
            status_code=200,
            json={"errors": [{"message": "Authentication required", "extensions": {"code": "AUTHENTICATION_ERROR"}}]},
        )
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Linear GraphQL returned errors"):
            await handler.fetch_identity(IdentityMaterial(access_token="bad-token"), config)

    async def test_http_error_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=LINEAR_GRAPHQL_URL, status_code=500, json={"error": "internal"})
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Linear identity"):
            await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=LINEAR_GRAPHQL_URL, status_code=200, content=b"not-json")
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse Linear identity response"):
            await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

    async def test_missing_data_object_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=LINEAR_GRAPHQL_URL, status_code=200, json={"data": None})
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="missing data"):
            await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

    async def test_missing_data_viewer_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=LINEAR_GRAPHQL_URL, status_code=200, json={"data": {}})
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="missing data.viewer"):
            await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)


class TestLinearPreset:
    def test_returns_a_configuration_its_provider_handler_resolves_from(self) -> None:
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(revocation_handler_for(config), RevocationHandler)

    def test_scope_separator_is_comma(self) -> None:
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read", "write"])
        assert config.scope_separator == ","

    def test_config_has_correct_endpoints(self) -> None:
        config = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        assert config.authorize_url == "https://linear.app/oauth/authorize"
        assert config.token_url == "https://api.linear.app/oauth/token"
        assert config.revocation_url == "https://api.linear.app/oauth/revoke"
