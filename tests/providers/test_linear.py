from __future__ import annotations

import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig, TenancyContext
from apron_auth.protocols import RevocationHandler
from apron_auth.providers.linear import LinearIdentityHandler, maybe_identity_handler, preset

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
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

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
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

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
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.tenancies == ()

    async def test_organization_id_present_but_name_and_url_key_missing(self, httpx_mock: HTTPXMock) -> None:
        viewer = {"id": "user-123"}
        organization = {"id": "org-1"}
        httpx_mock.add_response(
            url=LINEAR_GRAPHQL_URL,
            json={"data": {"viewer": viewer, "organization": organization}},
        )
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.tenancies == (TenancyContext(id="org-1", name=None, domain=None, raw=organization),)

    async def test_graphql_errors_in_200_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=LINEAR_GRAPHQL_URL,
            status_code=200,
            json={"errors": [{"message": "Authentication required", "extensions": {"code": "AUTHENTICATION_ERROR"}}]},
        )
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Linear GraphQL returned errors"):
            await handler.fetch_identity("bad-token", config)

    async def test_http_error_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=LINEAR_GRAPHQL_URL, status_code=500, json={"error": "internal"})
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Linear identity"):
            await handler.fetch_identity("access-abc", config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=LINEAR_GRAPHQL_URL, status_code=200, content=b"not-json")
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse Linear identity response"):
            await handler.fetch_identity("access-abc", config)

    async def test_missing_data_object_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=LINEAR_GRAPHQL_URL, status_code=200, json={"data": None})
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="missing data"):
            await handler.fetch_identity("access-abc", config)

    async def test_missing_data_viewer_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=LINEAR_GRAPHQL_URL, status_code=200, json={"data": {}})
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = LinearIdentityHandler()

        with pytest.raises(IdentityFetchError, match="missing data.viewer"):
            await handler.fetch_identity("access-abc", config)


class TestLinearMaybeIdentityHandler:
    def test_canonical_linear_host_returns_handler(self) -> None:
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        handler = maybe_identity_handler(config)
        assert isinstance(handler, LinearIdentityHandler)

    def test_lookalike_host_returns_none(self) -> None:
        config = ProviderConfig(
            client_id="lid",
            client_secret=SecretStr("lsecret"),  # pragma: allowlist secret
            authorize_url="https://linear.app.attacker.test/oauth/authorize",
            token_url="https://linear.app.attacker.test/oauth/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_authorize_url_matching_returns_none(self) -> None:
        config = ProviderConfig(
            client_id="lid",
            client_secret=SecretStr("lsecret"),  # pragma: allowlist secret
            authorize_url="https://linear.app/oauth/authorize",
            token_url="https://attacker.example.com/oauth/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_token_url_matching_returns_none(self) -> None:
        config = ProviderConfig(
            client_id="lid",
            client_secret=SecretStr("lsecret"),  # pragma: allowlist secret
            authorize_url="https://attacker.example.com/oauth/authorize",
            token_url="https://api.linear.app/oauth/token",
        )
        assert maybe_identity_handler(config) is None

    def test_non_linear_host_returns_none(self) -> None:
        config = ProviderConfig(
            client_id="lid",
            client_secret=SecretStr("lsecret"),  # pragma: allowlist secret
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
        )
        assert maybe_identity_handler(config) is None


class TestLinearPreset:
    def test_returns_config_and_handler(self) -> None:
        config, handler = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_scope_separator_is_comma(self) -> None:
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read", "write"])
        assert config.scope_separator == ","

    def test_config_has_correct_endpoints(self) -> None:
        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        assert config.authorize_url == "https://linear.app/oauth/authorize"
        assert config.token_url == "https://api.linear.app/oauth/token"
        assert config.revocation_url == "https://api.linear.app/oauth/revoke"
