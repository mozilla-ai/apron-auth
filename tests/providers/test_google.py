from __future__ import annotations

import asyncio
import traceback

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.errors import ConfigurationError, FailureKind, IdentityFetchError, RevocationError
from apron_auth.models import IdentityMaterial, ProviderConfig, TenancyContext, TimeoutPolicy
from apron_auth.protocols import RevocationHandler
from apron_auth.providers import revocation_handler_for
from apron_auth.providers.google import GoogleRevocationHandler

GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


class TestGoogleIdentityHandler:
    async def test_workspace_account_populates_domain_only(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "email": "user@mozilla.ai", "hd": "mozilla.ai"},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.provider == "google"
        assert identity.tenancies == (TenancyContext(domain="mozilla.ai", owns_email_domain=True),)

    async def test_workspace_account_owns_its_hosted_domain(self, httpx_mock: HTTPXMock):
        """End-to-end pin: a Workspace ``hd`` claim makes the emitted
        IdentityProfile assert ownership of that domain."""
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "email": "user@mozilla.ai", "hd": "mozilla.ai"},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.owns_domain("mozilla.ai") is True
        assert identity.owns_domain("other.example") is False
        assert [t.domain for t in identity.domain_owning_tenancies()] == ["mozilla.ai"]

    async def test_consumer_account_owns_no_domain(self, httpx_mock: HTTPXMock):
        """A personal Gmail account (no ``hd`` claim) emits no tenancy,
        so it must assert ownership of no domain."""
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "email": "user@gmail.com"},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.tenancies == ()
        assert identity.domain_owning_tenancies() == ()
        assert identity.owns_domain("gmail.com") is False

    async def test_consumer_account_yields_empty_tenancies(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "email": "user@gmail.com"},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.tenancies == ()

    async def test_empty_string_hd_yields_empty_tenancies(self, httpx_mock: HTTPXMock):
        """A pathologically-shaped response with ``hd=""`` must not
        emit a TenancyContext with ``domain=""`` — guard explicitly."""
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "hd": ""},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.tenancies == ()

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (True, True),
            (False, False),
            ("true", None),
            ("false", None),
            (1, None),
            (0, None),
            (None, None),
        ],
    )
    async def test_email_verified_honors_only_real_booleans(
        self, httpx_mock: HTTPXMock, value: object, expected: bool | None
    ):
        """A non-boolean email_verified is reported as unknown, not coerced —
        a bare bool() would read the string "false" as True."""
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "email": "user@gmail.com", "email_verified": value},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.email_verified is expected

    async def test_email_verified_absent_is_unknown(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=GOOGLE_USERINFO_URL,
            json={"sub": "g-1", "email": "user@gmail.com"},
        )
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        handler = GoogleIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.email_verified is None


class TestGooglePreset:
    def test_returns_a_configuration_its_provider_handler_resolves_from(self):
        from apron_auth.providers.google import preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        assert isinstance(config, ProviderConfig)
        assert revocation_handler_for(config) is not None
        assert isinstance(revocation_handler_for(config), RevocationHandler)

    def test_preset_declares_domain_ownership_capability(self):
        from apron_auth.providers.google import preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        assert config.can_assert_domain_ownership is True

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.google import preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        assert config.authorize_url == "https://accounts.google.com/o/oauth2/v2/auth"
        assert config.token_url == "https://oauth2.googleapis.com/token"
        assert config.revocation_url == "https://oauth2.googleapis.com/revoke"

    def test_extra_params_include_offline_access(self):
        from apron_auth.providers.google import preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        assert config.extra_params["access_type"] == "offline"
        assert config.extra_params["prompt"] == "consent"

    def test_extra_params_can_be_overridden(self):
        from apron_auth.providers.google import preset

        config = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["openid"],
            extra_params={"prompt": "select_account"},
        )
        assert config.extra_params["prompt"] == "select_account"
        assert config.extra_params["access_type"] == "offline"

    def test_redirect_uri_override(self):
        from apron_auth.providers.google import preset

        config = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["openid"],
            redirect_uri="https://custom.example.com/callback",
        )
        assert config.redirect_uri == "https://custom.example.com/callback"

    def test_base_scopes_merged_with_caller_scopes(self):
        from apron_auth.providers.google import BASE_SCOPES, preset

        config = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "https://www.googleapis.com/auth/gmail.readonly" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        from apron_auth.providers.google import preset

        config = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["openid", "https://www.googleapis.com/auth/gmail.readonly"],
        )
        assert config.scopes.count("openid") == 1

    def test_scope_metadata_covers_base_scopes(self):
        from apron_auth.providers.google import BASE_SCOPES, preset

        config = preset(
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

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        result = await GoogleRevocationHandler().revoke(SecretStr("access-abc"), config)
        assert result is True
        request = httpx_mock.get_request()
        assert request.method == "POST"
        assert "token=access-abc" in str(request.url)

    @pytest.mark.parametrize(
        "status",
        [
            pytest.param(202, id="a status stating the work is only accepted"),
            pytest.param(204, id="another success"),
        ],
    )
    async def test_a_success_google_does_not_state_is_refused(self, httpx_mock: HTTPXMock, status: int) -> None:
        """Google documents one status for a revocation it processed, so another states no outcome."""
        httpx_mock.add_response(status_code=status)
        from apron_auth.providers.google import preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])

        with pytest.raises(RevocationError, match="states no outcome") as refusal:
            await GoogleRevocationHandler().revoke(SecretStr("access-abc"), config)

        assert refusal.value.kind is FailureKind.REFUSED

    async def test_network_error_raises_revocation_error_without_the_token(self, httpx_mock: HTTPXMock) -> None:
        """The token is in the request URL, so the error has no cause or context."""
        secret = "access-SECRET-xyz"  # pragma: allowlist secret

        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"Connection refused for url {request.url}", request=request)

        httpx_mock.add_callback(refuse)
        from apron_auth.providers.google import preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])
        with pytest.raises(RevocationError) as exc_info:
            await GoogleRevocationHandler().revoke(SecretStr(secret), config)
        assert str(exc_info.value) == "Failed to revoke Google token: network error"
        formatted = "".join(traceback.format_exception(exc_info.value))
        assert secret not in formatted
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"error": "invalid_token"}, id="a code naming the token"),
            pytest.param({"error": ["invalid_token"]}, id="a code of another JSON type"),
            pytest.param({}, id="no error member"),
        ],
    )
    async def test_the_error_status_reads_as_the_token_already_being_invalid(
        self, httpx_mock: HTTPXMock, body: dict[str, object]
    ) -> None:
        """Google states one error status and no codes, so the body it carries decides nothing."""
        httpx_mock.add_response(status_code=400, json=body)
        from apron_auth.providers.google import preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])

        assert await GoogleRevocationHandler().revoke(SecretStr("access-abc"), config) is True

    @pytest.mark.parametrize("status", [401, 403, 404, 418])
    async def test_a_status_google_states_nothing_about_is_still_refused(
        self, httpx_mock: HTTPXMock, status: int
    ) -> None:
        httpx_mock.add_response(status_code=status)
        from apron_auth.providers.google import preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])

        with pytest.raises(RevocationError) as refusal:
            await GoogleRevocationHandler().revoke(SecretStr("access-abc"), config)

        assert refusal.value.kind is FailureKind.REJECTED

    @pytest.mark.parametrize("token", ["", " ", "\t"])
    async def test_a_request_naming_no_token_is_refused_before_it_is_sent(
        self, httpx_mock: HTTPXMock, token: str
    ) -> None:
        """The error status states the token, which holds only for a request that named one."""
        from apron_auth.providers.google import preset

        config = preset(client_id="gid", client_secret="gsecret", scopes=["openid"])

        with pytest.raises(ConfigurationError) as refusal:
            await GoogleRevocationHandler().revoke(SecretStr(token), config)

        assert refusal.value.kind is FailureKind.CONFIGURATION
        assert httpx_mock.get_requests() == []


class TestTheTimeoutPolicyBoundsTheIdentityRequest:
    async def test_a_userinfo_response_that_never_lands_is_refused_as_a_timeout(self, httpx_mock: HTTPXMock) -> None:
        """A handler builds its own client, so this is the only place a caller's limits can reach the request."""

        async def crawl(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(5)
            return httpx.Response(200, json={"sub": "g-1"})

        httpx_mock.add_callback(crawl, url=GOOGLE_USERINFO_URL)
        from apron_auth.providers.google import GoogleIdentityHandler, preset

        config = preset(
            client_id="gid",
            client_secret="gsecret",  # pragma: allowlist secret
            scopes=["openid"],
            timeouts=TimeoutPolicy(connect_seconds=0.05, request_seconds=0.05),
        )

        with pytest.raises(IdentityFetchError) as refusal:
            await GoogleIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert refusal.value.kind is FailureKind.TIMEOUT
