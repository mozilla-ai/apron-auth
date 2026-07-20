from __future__ import annotations

import base64
import json
import logging

import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityMaterial, IdentityProfile, ProviderConfig, TenancyContext

_USERINFO_URL = "https://graph.microsoft.com/oidc/userinfo"
_ORGANIZATION_URL = "https://graph.microsoft.com/v1.0/organization"

_TENANT_ID = "11111111-2222-3333-4444-555555555555"
_ISSUER = f"https://login.microsoftonline.com/{_TENANT_ID}/v2.0"
_CONSUMERS_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"

_USERINFO = {
    "sub": "ms-user-123",
    "email": "user@contoso.com",
    "name": "Test User",
    "picture": "https://example.com/avatar.png",
}


def _fake_jwt(payload: dict[str, object]) -> str:
    """Build a header.payload.signature string with a base64url payload.

    The signature segment is intentionally bogus — the handler does not
    verify ID-token signatures (the token arrives over the back-channel),
    so the parser only cares about the middle segment shape.
    """

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    return f"{header}.{body}.sig"


def _member_id_token(**overrides: object) -> str:
    """Build an ID token for a workforce member of the test tenant."""
    claims: dict[str, object] = {
        "tid": _TENANT_ID,
        "iss": _ISSUER,
        "sub": "ms-sub-1",
        "oid": "ms-oid-1",
    }
    claims.update(overrides)
    return _fake_jwt(claims)


def _org_response(
    domains: list[str],
    *,
    org_id: str = _TENANT_ID,
    display_name: object = "Contoso",
) -> dict[str, object]:
    """Build a Graph ``/v1.0/organization`` collection response."""
    organization: dict[str, object] = {
        "id": org_id,
        "verifiedDomains": [{"name": name, "isDefault": False} for name in domains],
    }
    if display_name is not None:
        organization["displayName"] = display_name
    return {"value": [organization]}


def _config() -> ProviderConfig:
    from apron_auth.providers.microsoft import preset

    config, _ = preset(client_id="mid", client_secret="msecret", scopes=["openid"])
    return config


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

    def test_can_assert_domain_ownership(self):
        from apron_auth.providers.microsoft import preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert config.can_assert_domain_ownership is True

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


class TestMicrosoftIdentityNoVerifiedTenancy:
    """Sign-ins that resolve identity but assert no domain-owning tenancy."""

    async def test_no_id_token_returns_identity_without_tenancy(self, httpx_mock: HTTPXMock):
        """Without an ID token the access-token ``tid`` is not used as a
        fallback tenancy; identity is still returned from userinfo."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc"), _config()
        )

        assert identity == IdentityProfile(
            provider="microsoft",
            subject="ms-user-123",
            email="user@contoso.com",
            email_verified=None,
            name="Test User",
            avatar_url="https://example.com/avatar.png",
            tenancies=(),
            raw=_USERINFO,
        )
        request = httpx_mock.get_request()
        assert request.headers.get("authorization") == "Bearer access-abc"

    async def test_personal_account_tenant_yields_no_tenancy(self, httpx_mock: HTTPXMock):
        """The well-known consumers tenant is a personal account, not a
        workforce tenant; no organization lookup is performed."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        id_token = _fake_jwt(
            {
                "tid": _CONSUMERS_TENANT,
                "iss": f"https://login.microsoftonline.com/{_CONSUMERS_TENANT}/v2.0",
                "sub": "ms-sub-1",
            }
        )
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.tenancies == ()
        # ``sub`` still comes from the validated ID token.
        assert identity.subject == "ms-sub-1"

    async def test_b2b_guest_yields_no_tenancy(self, httpx_mock: HTTPXMock):
        """A guest signs in with the host tenant's ``tid`` but is not a
        member; the differing ``idp`` claim must suppress the tenancy."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        id_token = _member_id_token(idp="https://login.microsoftonline.com/home-tenant/v2.0")
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.tenancies == ()

    async def test_idp_equal_to_iss_is_treated_as_member(self, httpx_mock: HTTPXMock):
        """An ``idp`` claim equal to ``iss`` is a member, not a guest."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"]))
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        id_token = _member_id_token(idp=_ISSUER)
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.tenancies == (
            TenancyContext(id=_TENANT_ID, name="Contoso", domain="contoso.com", owns_email_domain=True),
        )

    @pytest.mark.parametrize(
        "bad_tid",
        ["not-a-guid", "1234", "11111111222233334444555555555555", 12345, "", None],
    )
    async def test_non_guid_tid_yields_no_tenancy(self, httpx_mock: HTTPXMock, bad_tid: object):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        id_token = _fake_jwt({"tid": bad_tid, "iss": _ISSUER, "sub": "ms-sub-1"})
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.tenancies == ()

    async def test_issuer_not_bound_to_tid_yields_no_tenancy(self, httpx_mock: HTTPXMock):
        """``iss`` must equal ``.../{tid}/v2.0``; an issuer naming a
        different tenant breaks the chain of trust."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        id_token = _member_id_token(iss="https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0")
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.tenancies == ()

    @pytest.mark.parametrize(
        "malformed",
        [
            "single-segment-token",
            "header-only.",
            "header.!!!not-valid-base64!!!.sig",
            "header.eyJ0aWQ.sig",  # truncated payload
            "header.aGVsbG8.sig",  # base64-decodes to "hello", not JSON
        ],
    )
    async def test_malformed_id_token_yields_identity_without_tenancy(self, httpx_mock: HTTPXMock, malformed: str):
        """A malformed ID token must degrade to ``tenancies=()`` while
        still returning identity from userinfo — never raise."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=malformed), _config()
        )

        assert identity.tenancies == ()
        # Falls back to the userinfo subject when the ID token is unusable.
        assert identity.subject == "ms-user-123"


class TestMicrosoftVerifiedTenancy:
    """Workforce members whose verified domains resolve to tenancies."""

    async def test_single_verified_domain(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"]))
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
        )

        assert identity.subject == "ms-sub-1"
        assert identity.tenancies == (
            TenancyContext(id=_TENANT_ID, name="Contoso", domain="contoso.com", owns_email_domain=True),
        )
        assert identity.owns_domain("contoso.com") is True

    async def test_multiple_verified_domains_emit_one_tenancy_each(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(
            url=_ORGANIZATION_URL,
            json=_org_response(["contoso.com", "contoso.co.uk", "contoso.onmicrosoft.com"]),
        )
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
        )

        assert identity.tenancies == (
            TenancyContext(id=_TENANT_ID, name="Contoso", domain="contoso.com", owns_email_domain=True),
            TenancyContext(id=_TENANT_ID, name="Contoso", domain="contoso.co.uk", owns_email_domain=True),
            TenancyContext(id=_TENANT_ID, name="Contoso", domain="contoso.onmicrosoft.com", owns_email_domain=True),
        )

    async def test_every_verified_domain_is_gateable(self, httpx_mock: HTTPXMock) -> None:
        """Every verified domain of a tenant must satisfy the gate.

        Graph does not guarantee the order it lists verified domains in, so
        gating must not depend on which one it happened to return first.
        """
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(
            url=_ORGANIZATION_URL,
            json=_org_response(["contoso.onmicrosoft.com", "contoso.com", "contoso.co.uk"]),
        )
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
        )

        assert identity.owns_domain("contoso.com") is True
        assert identity.owns_domain("contoso.co.uk") is True
        assert identity.owns_domain("contoso.onmicrosoft.com") is True
        assert identity.owns_domain("fabrikam.com") is False

    async def test_missing_display_name_still_emits_tenancy(self, httpx_mock: HTTPXMock):
        """``displayName`` is decorative; its absence must not drop the
        tenancy, only leave ``name`` as ``None``."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"], display_name=None))
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
        )

        assert identity.tenancies == (
            TenancyContext(id=_TENANT_ID, name=None, domain="contoso.com", owns_email_domain=True),
        )

    async def test_email_verified_honored_from_id_token(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"]))
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token(email_verified=True)),
            _config(),
        )

        assert identity.email_verified is True

    async def test_organization_id_mismatch_suppresses_tenancy(self, httpx_mock: HTTPXMock, caplog):
        """If the directory lookup resolves a different tenant than the
        validated ID token, refuse to assert ownership."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(
            url=_ORGANIZATION_URL,
            json=_org_response(["contoso.com"], org_id="99999999-9999-9999-9999-999999999999"),
        )
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        with caplog.at_level(logging.WARNING):
            identity = await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

        assert identity.tenancies == ()
        assert "does not match the validated tenant" in caplog.text

    async def test_no_verified_domains_yields_no_tenancy(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response([]))
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
        )

        assert identity.tenancies == ()


class TestMicrosoftEmailVerified:
    """email_verified is honored only as a genuine boolean from the signature-unverified ID token."""

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
        a bare bool() would read the string "false" as True. Uses the
        consumers-tenant path so no organization lookup is triggered."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        id_token = _fake_jwt(
            {
                "tid": _CONSUMERS_TENANT,
                "iss": f"https://login.microsoftonline.com/{_CONSUMERS_TENANT}/v2.0",
                "sub": "ms-sub-1",
                "email_verified": value,
            }
        )
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.email_verified is expected

    async def test_email_verified_absent_is_unknown(self, httpx_mock: HTTPXMock):
        """An ID token with no email_verified claim yields None."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        id_token = _fake_jwt(
            {
                "tid": _CONSUMERS_TENANT,
                "iss": f"https://login.microsoftonline.com/{_CONSUMERS_TENANT}/v2.0",
                "sub": "ms-sub-1",
            }
        )
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.email_verified is None


class TestMicrosoftIdentityErrors:
    async def test_userinfo_401_raises(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, status_code=401, json={"error": "invalid_token"})
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        with pytest.raises(IdentityFetchError, match="Failed to fetch Microsoft identity"):
            await MicrosoftIdentityHandler().fetch_identity(IdentityMaterial(access_token="bad-token"), _config())

    async def test_userinfo_non_json_raises(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, status_code=200, content=b"not-json")
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        with pytest.raises(IdentityFetchError, match="Failed to parse Microsoft identity response"):
            await MicrosoftIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), _config())

    async def test_organization_call_failure_raises(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, status_code=403, json={"error": "forbidden"})
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        with pytest.raises(IdentityFetchError, match="Failed to fetch Microsoft organization"):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

    async def test_organization_non_json_raises(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, status_code=200, content=b"not-json")
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        with pytest.raises(IdentityFetchError, match="Failed to parse Microsoft organization response"):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

    async def test_organization_empty_collection_raises(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json={"value": []})
        from apron_auth.providers.microsoft import MicrosoftIdentityHandler

        with pytest.raises(IdentityFetchError, match="contained no organization"):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )


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

    def test_only_authorize_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.microsoft import maybe_identity_handler

        config = ProviderConfig(
            client_id="mid",
            client_secret=SecretStr("msecret"),  # pragma: allowlist secret
            authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://attacker.example.com/common/oauth2/v2.0/token",
        )
        assert maybe_identity_handler(config) is None

    def test_only_token_url_matching_returns_none(self):
        from pydantic import SecretStr

        from apron_auth.providers.microsoft import maybe_identity_handler

        config = ProviderConfig(
            client_id="mid",
            client_secret=SecretStr("msecret"),  # pragma: allowlist secret
            authorize_url="https://attacker.example.com/common/oauth2/v2.0/authorize",
            token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        )
        assert maybe_identity_handler(config) is None
