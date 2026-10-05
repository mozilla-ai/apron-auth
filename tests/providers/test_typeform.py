from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError, IdentityScopeNotGrantedError
from apron_auth.models import IdentityMaterial, IdentityProfile, ProviderConfig


class TestTypeformPreset:
    def test_returns_config_and_none_handler(self):
        from apron_auth.providers.typeform import preset

        config, handler = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        assert isinstance(config, ProviderConfig)
        assert handler is None

    def test_pkce_disabled(self):
        from apron_auth.providers.typeform import preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        assert config.use_pkce is False

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.typeform import preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        assert config.authorize_url == "https://api.typeform.com/oauth/authorize"
        assert config.token_url == "https://api.typeform.com/oauth/token"
        assert config.revocation_url is None


class TestTypeformIdentityHandler:
    async def test_happy_path_returns_identity_profile(self, httpx_mock: HTTPXMock):
        payload = {
            "alias": "octouser",
            "email": "user@example.com",
            "language": "en",
        }
        httpx_mock.add_response(url="https://api.typeform.com/me", json=payload)
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        handler = TypeformIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity == IdentityProfile(
            provider="typeform",
            subject=None,
            email="user@example.com",
            email_verified=None,
            name=None,
            username="octouser",
            avatar_url=None,
            raw=payload,
        )
        # Typeform "workspaces" are intra-account containers, not
        # OAuth-scoping contexts. Assert ``()`` explicitly so a future
        # change that surfaces workspaces as tenants trips this test.
        assert identity.tenancies == ()
        request = httpx_mock.get_request()
        assert request.headers.get("authorization") == "Bearer access-abc"

    async def test_subject_is_none_even_when_payload_has_id_like_field(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.typeform.com/me",
            json={
                "alias": "octouser",
                "email": "user@example.com",
                "language": "en",
                "id": "should-be-ignored",
                "user_id": "should-also-be-ignored",
            },
        )
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        handler = TypeformIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.subject is None

    async def test_401_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.typeform.com/me",
            status_code=401,
            json={"error": "invalid_token"},
        )
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        handler = TypeformIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Typeform identity"):
            await handler.fetch_identity(IdentityMaterial(access_token="bad-token"), config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://api.typeform.com/me",
            status_code=200,
            content=b"not-json",
        )
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        handler = TypeformIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse Typeform identity response"):
            await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

    async def test_granted_scope_without_accounts_read_raises_scope_not_granted(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read", "forms:read"])
        material = IdentityMaterial(access_token="access-abc", scope="forms:read")

        with pytest.raises(IdentityScopeNotGrantedError, match="accounts:read"):
            await TypeformIdentityHandler().fetch_identity(material, config)
        assert httpx_mock.get_requests() == []

    @pytest.mark.parametrize("blank_scope", ["", "   ", ","])
    async def test_blank_granted_scope_is_treated_as_unknown(self, httpx_mock: HTTPXMock, blank_scope: str) -> None:
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        httpx_mock.add_response(url="https://api.typeform.com/me", json={"email": "user@example.com"})
        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        config = config.model_copy(update={"scope_separator": ","})
        material = IdentityMaterial(access_token="access-abc", scope=blank_scope)

        identity = await TypeformIdentityHandler().fetch_identity(material, config)

        assert identity.email == "user@example.com"

    async def test_unknown_grant_requests_identity_even_when_config_lacks_accounts_read(
        self, httpx_mock: HTTPXMock
    ) -> None:
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        httpx_mock.add_response(url="https://api.typeform.com/me", json={"email": "user@example.com"})
        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["forms:read"])

        identity = await TypeformIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.email == "user@example.com"

    async def test_unknown_grant_403_raises_generic_error(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        httpx_mock.add_response(
            url="https://api.typeform.com/me",
            status_code=403,
            json={"code": "AUTHENTICATION_ERROR", "description": "The access token is incorrect"},
        )
        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["forms:read"])

        with pytest.raises(IdentityFetchError) as exc_info:
            await TypeformIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), config)
        assert not isinstance(exc_info.value, IdentityScopeNotGrantedError)

    async def test_granted_accounts_read_overrides_config(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        httpx_mock.add_response(url="https://api.typeform.com/me", json={"email": "user@example.com"})
        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["forms:read"])
        material = IdentityMaterial(access_token="access-abc", scope="forms:read accounts:read")

        identity = await TypeformIdentityHandler().fetch_identity(material, config)

        assert identity.email == "user@example.com"

    async def test_granted_scope_parsed_with_config_separator(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        httpx_mock.add_response(url="https://api.typeform.com/me", json={"email": "user@example.com"})
        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        config = config.model_copy(update={"scope_separator": ","})
        material = IdentityMaterial(access_token="access-abc", scope="forms:read,accounts:read")

        identity = await TypeformIdentityHandler().fetch_identity(material, config)

        assert identity.email == "user@example.com"

    async def test_granted_scope_implying_accounts_read_is_accepted(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        httpx_mock.add_response(url="https://api.typeform.com/me", json={"email": "user@example.com"})
        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:write"])
        config = config.model_copy(update={"implicit_scopes": {"accounts:write": frozenset({"accounts:read"})}})
        material = IdentityMaterial(access_token="access-abc", scope="accounts:write")

        identity = await TypeformIdentityHandler().fetch_identity(material, config)

        assert identity.email == "user@example.com"

    async def test_403_with_accounts_read_granted_raises_generic_error(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        httpx_mock.add_response(
            url="https://api.typeform.com/me",
            status_code=403,
            json={"code": "AUTHENTICATION_ERROR", "description": "The access token is incorrect"},
        )
        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        material = IdentityMaterial(access_token="access-abc", scope="accounts:read")

        with pytest.raises(IdentityFetchError) as exc_info:
            await TypeformIdentityHandler().fetch_identity(material, config)
        assert not isinstance(exc_info.value, IdentityScopeNotGrantedError)

    async def test_non_object_json_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.typeform import TypeformIdentityHandler, preset

        httpx_mock.add_response(url="https://api.typeform.com/me", json=["not", "an", "object"])
        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])

        with pytest.raises(IdentityFetchError, match="not a JSON object"):
            await TypeformIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), config)


class TestTypeformMaybeIdentityHandler:
    def test_canonical_typeform_host_returns_handler(self):
        from apron_auth.providers.typeform import TypeformIdentityHandler, maybe_identity_handler, preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        handler = maybe_identity_handler(config)
        assert isinstance(handler, TypeformIdentityHandler)

    def test_lookalike_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.typeform import maybe_identity_handler

        config = ProviderConfig(
            client_id="tid",
            client_secret=SecretStr("tsecret"),  # pragma: allowlist secret
            authorize_url="https://eviltypeform.com/oauth/authorize",
            token_url="https://eviltypeform.com/oauth/token",
        )
        assert maybe_identity_handler(config) is None

    def test_non_typeform_host_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.typeform import maybe_identity_handler

        config = ProviderConfig(
            client_id="tid",
            client_secret=SecretStr("tsecret"),  # pragma: allowlist secret
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_authorize_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.typeform import maybe_identity_handler

        config = ProviderConfig(
            client_id="tid",
            client_secret=SecretStr("tsecret"),  # pragma: allowlist secret
            authorize_url="https://api.typeform.com/oauth/authorize",
            token_url="https://attacker.example.com/oauth/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_token_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.typeform import maybe_identity_handler

        config = ProviderConfig(
            client_id="tid",
            client_secret=SecretStr("tsecret"),  # pragma: allowlist secret
            authorize_url="https://attacker.example.com/oauth/authorize",
            token_url="https://api.typeform.com/oauth/token",
        )
        assert maybe_identity_handler(config) is None
