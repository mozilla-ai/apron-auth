from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig, TenancyContext
from apron_auth.protocols import RevocationHandler

ATLASSIAN_ME_URL = "https://api.atlassian.com/me"
ATLASSIAN_ACCESSIBLE_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"


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
        resources = [
            {
                "id": "cloud-1",
                "name": "Acme Corp",
                "url": "https://acme.atlassian.net",
                "scopes": ["read:jira-work"],
                "avatarUrl": "https://example.com/site-avatar.png",
            }
        ]
        httpx_mock.add_response(url=ATLASSIAN_ME_URL, json=payload)
        httpx_mock.add_response(url=ATLASSIAN_ACCESSIBLE_RESOURCES_URL, json=resources)
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity == IdentityProfile(
            provider="atlassian",
            subject="557058:abc-123",
            email="user@example.com",
            email_verified=None,
            name="Test User",
            username="tuser",
            avatar_url="https://example.com/avatar.png",
            tenancies=(
                TenancyContext(
                    id="cloud-1",
                    name="Acme Corp",
                    domain="https://acme.atlassian.net",
                    raw={
                        "scopes": ["read:jira-work"],
                        "avatarUrl": "https://example.com/site-avatar.png",
                    },
                ),
            ),
            raw=payload,
        )
        requests = httpx_mock.get_requests()
        assert {str(r.url) for r in requests} == {
            ATLASSIAN_ME_URL,
            ATLASSIAN_ACCESSIBLE_RESOURCES_URL,
        }
        for request in requests:
            assert request.headers.get("authorization") == "Bearer access-abc"

    async def test_multi_tenant_token_emits_one_context_per_resource(self, httpx_mock: HTTPXMock):
        """Atlassian is the canonical multi-tenant case — load-bearing
        validation that ``tenancies`` is a tuple, not a singleton."""
        payload = {"account_id": "557058:abc-123", "name": "Test User"}
        resources = [
            {
                "id": "cloud-1",
                "name": "Acme Corp",
                "url": "https://acme.atlassian.net",
                "scopes": ["read:jira-work"],
            },
            {
                "id": "cloud-2",
                "name": "Beta Org",
                "url": "https://beta.atlassian.net",
                "scopes": ["read:confluence-content.summary"],
            },
        ]
        httpx_mock.add_response(url=ATLASSIAN_ME_URL, json=payload)
        httpx_mock.add_response(url=ATLASSIAN_ACCESSIBLE_RESOURCES_URL, json=resources)
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert len(identity.tenancies) == 2
        assert identity.tenancies[0].id == "cloud-1"
        assert identity.tenancies[1].id == "cloud-2"
        assert identity.tenancies[1].domain == "https://beta.atlassian.net"

    async def test_empty_accessible_resources_yields_empty_tenancies(self, httpx_mock: HTTPXMock):
        payload = {"account_id": "557058:abc-123"}
        httpx_mock.add_response(url=ATLASSIAN_ME_URL, json=payload)
        httpx_mock.add_response(url=ATLASSIAN_ACCESSIBLE_RESOURCES_URL, json=[])
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.tenancies == ()

    async def test_resource_without_id_is_skipped(self, httpx_mock: HTTPXMock):
        """A resource entry that lacks ``id`` cannot be keyed and must
        be silently dropped; other entries in the same response are
        kept so a malformed item does not poison the whole list."""
        payload = {"account_id": "557058:abc-123"}
        resources = [
            {"name": "Missing ID", "url": "https://no-id.atlassian.net"},
            {"id": "cloud-2", "name": "Acme", "url": "https://acme.atlassian.net"},
        ]
        httpx_mock.add_response(url=ATLASSIAN_ME_URL, json=payload)
        httpx_mock.add_response(url=ATLASSIAN_ACCESSIBLE_RESOURCES_URL, json=resources)
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert len(identity.tenancies) == 1
        assert identity.tenancies[0].id == "cloud-2"

    async def test_non_dict_resource_items_are_skipped(self, httpx_mock: HTTPXMock):
        payload = {"account_id": "557058:abc-123"}
        resources = ["not-a-dict", None, {"id": "cloud-1", "name": "Acme"}]
        httpx_mock.add_response(url=ATLASSIAN_ME_URL, json=payload)
        httpx_mock.add_response(url=ATLASSIAN_ACCESSIBLE_RESOURCES_URL, json=resources)
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert len(identity.tenancies) == 1
        assert identity.tenancies[0].id == "cloud-1"

    async def test_non_list_accessible_resources_yields_empty_tenancies(self, httpx_mock: HTTPXMock):
        """If Atlassian returns an unexpected non-list shape (e.g. an
        object), degrade cleanly to empty rather than raising."""
        payload = {"account_id": "557058:abc-123"}
        httpx_mock.add_response(url=ATLASSIAN_ME_URL, json=payload)
        httpx_mock.add_response(
            url=ATLASSIAN_ACCESSIBLE_RESOURCES_URL,
            json={"unexpected": "object"},
        )
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        identity = await handler.fetch_identity("access-abc", config)

        assert identity.tenancies == ()

    async def test_401_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=ATLASSIAN_ME_URL,
            status_code=401,
            json={"error": "invalid_token"},
        )
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Atlassian identity"):
            await handler.fetch_identity("bad-token", config)

    async def test_accessible_resources_failure_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=ATLASSIAN_ME_URL, json={"account_id": "x"})
        httpx_mock.add_response(
            url=ATLASSIAN_ACCESSIBLE_RESOURCES_URL,
            status_code=500,
            json={"error": "internal"},
        )
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        # Distinct message per sub-request so log triage can identify
        # which endpoint failed without reproducing the call.
        with pytest.raises(IdentityFetchError, match="Failed to fetch Atlassian accessible resources"):
            await handler.fetch_identity("access-abc", config)

    async def test_accessible_resources_non_json_raises_distinct_parse_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=ATLASSIAN_ME_URL, json={"account_id": "x"})
        httpx_mock.add_response(
            url=ATLASSIAN_ACCESSIBLE_RESOURCES_URL,
            status_code=200,
            content=b"not-json",
        )
        from apron_auth.providers.atlassian import AtlassianIdentityHandler, preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:me"])
        handler = AtlassianIdentityHandler()

        with pytest.raises(
            IdentityFetchError,
            match="Failed to parse Atlassian accessible resources response",
        ):
            await handler.fetch_identity("access-abc", config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=ATLASSIAN_ME_URL,
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
