from __future__ import annotations

import json
import logging
import time

import httpx
import pytest
from joserfc import jwk, jws
from pytest_httpx import HTTPXMock

from apron_auth.client import OAuthClient
from apron_auth.errors import IdentityFetchError, TokenExpiredError, TokenValidationError, TokenValidationReason
from apron_auth.models import FreshTokenSet, IdentityMaterial, IdentityProfile, ProviderConfig, TenancyContext
from apron_auth.providers.microsoft import MicrosoftIdentityHandler, preset

_USERINFO_URL = "https://graph.microsoft.com/oidc/userinfo"
_ORGANIZATION_URL = "https://graph.microsoft.com/v1.0/organization"
_KEYS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

_CLIENT_ID = "mid"
_TENANT_ID = "11111111-2222-3333-4444-555555555555"
_ISSUER = f"https://login.microsoftonline.com/{_TENANT_ID}/v2.0"
_CONSUMERS_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"

_USERINFO = {
    "sub": "ms-sub-1",
    "email": "user@contoso.com",
    "name": "Test User",
    "picture": "https://example.com/avatar.png",
}


_SIGNING_KEY = jwk.RSAKey.generate_key(2048, parameters={"kid": "ms-key-1"})
_PUBLISHED_KEYS = {"keys": [_SIGNING_KEY.as_dict(private=False)]}


@pytest.fixture(autouse=True)
def _published_keys(httpx_mock: HTTPXMock) -> None:
    """Serve Microsoft's key set to any test that sends an ID token."""
    httpx_mock.add_response(url=_KEYS_URL, json=_PUBLISHED_KEYS, is_optional=True, is_reusable=True)


_OMIT = object()
"""Sentinel letting a test leave out a claim the helper otherwise always sets."""


def _fake_jwt(payload: dict[str, object], *, key: jwk.RSAKey = _SIGNING_KEY) -> str:
    """Return an ID token signed with Microsoft's published test key, carrying ``payload``.

    ``aud``, ``exp`` and ``iat`` are set for the test client unless ``payload`` gives them.
    Pass ``_OMIT`` for a claim to leave it out, and ``key`` to sign with a key Microsoft does not publish.
    """
    now = int(time.time())
    claims = {"aud": _CLIENT_ID, "exp": now + 300, "iat": now, **payload}
    claims = {name: value for name, value in claims.items() if value is not _OMIT}
    return jws.serialize_compact({"alg": "RS256", "kid": "ms-key-1"}, json.dumps(claims).encode(), key)


def _member_id_token(*, key: jwk.RSAKey = _SIGNING_KEY, **overrides: object) -> str:
    """Build an ID token for a workforce member of the test tenant, signed with ``key``."""
    claims: dict[str, object] = {
        "tid": _TENANT_ID,
        "iss": _ISSUER,
        "sub": "ms-sub-1",
        "oid": "ms-oid-1",
    }
    claims.update(overrides)
    return _fake_jwt(claims, key=key)


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

    config, _ = preset(client_id=_CLIENT_ID, client_secret="msecret", scopes=["openid"])
    return config


class TestMicrosoftPreset:
    def test_returns_config_and_none_handler(self):
        from apron_auth.providers.microsoft import preset

        config, handler = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert isinstance(config, ProviderConfig)
        assert handler is None

    def test_a_guid_client_id_is_lowercased(self):
        """Entra names the client by its lowercase GUID in an ID token's audience."""
        from apron_auth.providers.microsoft import preset

        guid = "ABCDEF12-3456-7890-ABCD-EF1234567890"
        config, _ = preset(client_id=guid, client_secret="msecret", scopes=[])
        assert config.client_id == guid.lower()

    def test_a_client_id_that_is_not_a_guid_is_kept(self):
        from apron_auth.providers.microsoft import preset

        config, _ = preset(client_id="My-App", client_secret="msecret", scopes=[])
        assert config.client_id == "My-App"

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
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc"), _config()
        )

        assert identity == IdentityProfile(
            provider="microsoft",
            subject="ms-sub-1",
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
        id_token = _member_id_token(idp="https://login.microsoftonline.com/home-tenant/v2.0")
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.tenancies == ()

    @pytest.mark.parametrize("idp", [None, ["https://x"], 5, ""])
    async def test_an_idp_that_is_not_the_issuer_yields_no_tenancy(self, httpx_mock: HTTPXMock, idp: object) -> None:
        """Any ``idp`` that is present and not exactly the issuer marks a guest, whatever its JSON type."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token(idp=idp)), _config()
        )

        assert identity.tenancies == ()

    async def test_idp_equal_to_iss_is_treated_as_member(self, httpx_mock: HTTPXMock):
        """An ``idp`` claim equal to ``iss`` is a member, not a guest."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"]))
        id_token = _member_id_token(idp=_ISSUER)
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.tenancies == (
            TenancyContext(id=_TENANT_ID, name="Contoso", domain="contoso.com", owns_email_domain=True),
        )


class TestMicrosoftVerifiedTenancy:
    """Workforce members whose verified domains resolve to tenancies."""

    async def test_single_verified_domain(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"]))
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
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
        )

        assert identity.tenancies == (
            TenancyContext(id=_TENANT_ID, name=None, domain="contoso.com", owns_email_domain=True),
        )

    async def test_email_verified_honored_from_id_token(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"]))
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(
                access_token="access-abc", id_token=_member_id_token(email="user@contoso.com", email_verified=True)
            ),
            _config(),
        )

        assert identity.email_verified is True

    async def test_organization_id_mismatch_suppresses_tenancy(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ):
        """If the directory lookup resolves a different tenant than the
        validated ID token, refuse to assert ownership."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(
            url=_ORGANIZATION_URL,
            json=_org_response(["contoso.com"], org_id="99999999-9999-9999-9999-999999999999"),
        )
        with caplog.at_level(logging.WARNING):
            identity = await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

        assert identity.tenancies == ()
        assert "does not match the validated tenant" in caplog.text

    async def test_no_verified_domains_yields_no_tenancy(self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response([]))
        with caplog.at_level(logging.WARNING):
            identity = await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

        assert identity.tenancies == ()
        assert "no usable verified domains" in caplog.text

    @pytest.mark.parametrize(
        "verified_domains",
        [
            pytest.param("contoso.com", id="not-a-list"),
            pytest.param([{"isDefault": True}], id="entries-without-a-name"),
            pytest.param([{"name": ""}], id="entries-with-a-blank-name"),
        ],
    )
    async def test_unusable_verified_domains_warn(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture, verified_domains: object
    ):
        """Withholding must never be silent, whatever shape the field takes.

        A malformed or unusable ``verifiedDomains`` withholds domain
        ownership exactly as a failed lookup does, so it has to be as
        observable — the consumer-visible symptom is identical.
        """
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(
            url=_ORGANIZATION_URL,
            json={"value": [{"id": _TENANT_ID, "displayName": "Contoso", "verifiedDomains": verified_domains}]},
        )
        with caplog.at_level(logging.WARNING):
            identity = await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

        assert identity.subject == "ms-sub-1"
        assert identity.tenancies == ()
        assert identity.owns_domain("contoso.com") is False
        assert "no usable verified domains" in caplog.text


class TestMicrosoftEmailVerified:
    """email_verified is honored only as a genuine boolean that the ID token asserts for the reported email."""

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
        id_token = _fake_jwt(
            {
                "tid": _CONSUMERS_TENANT,
                "iss": f"https://login.microsoftonline.com/{_CONSUMERS_TENANT}/v2.0",
                "sub": "ms-sub-1",
                "email": "user@contoso.com",
                "email_verified": value,
            }
        )
        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
        )

        assert identity.email_verified is expected

    @pytest.mark.parametrize("id_token_email", ["someone@else.com", None, "USER@contoso.com"])
    async def test_email_verified_is_unknown_for_another_email(
        self, httpx_mock: HTTPXMock, id_token_email: str | None
    ) -> None:
        """The ID token vouches only for the email it names, so a different or absent email gives no assertion."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        claims: dict[str, object] = {"email_verified": True}
        if id_token_email is not None:
            claims["email"] = id_token_email

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(
                access_token="access-abc",
                id_token=_fake_jwt(
                    {
                        "tid": _CONSUMERS_TENANT,
                        "iss": f"https://login.microsoftonline.com/{_CONSUMERS_TENANT}/v2.0",
                        "sub": "ms-sub-1",
                        **claims,
                    }
                ),
            ),
            _config(),
        )

        assert identity.email == "user@contoso.com"
        assert identity.email_verified is None

    async def test_email_verified_absent_is_unknown(self, httpx_mock: HTTPXMock):
        """An ID token with no email_verified claim yields None."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
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
        with pytest.raises(IdentityFetchError, match="Failed to fetch Microsoft identity"):
            await MicrosoftIdentityHandler().fetch_identity(IdentityMaterial(access_token="bad-token"), _config())

    async def test_userinfo_non_json_raises(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_USERINFO_URL, status_code=200, content=b"not-json")
        with pytest.raises(IdentityFetchError, match="Failed to parse Microsoft identity response"):
            await MicrosoftIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), _config())


class TestMicrosoftOrganizationDegradation:
    """A failed organization lookup withholds tenancy without blocking sign-in.

    The lookup only enriches tenancy — identity is already established by
    the userinfo call — so every failure mode degrades to ``tenancies=()``.
    That withholds the domain-ownership assertion, which closes rather
    than opens any consumer gate keyed on ``owns_domain()``.
    """

    async def test_forbidden_degrades_to_no_tenancy(self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, status_code=403, json={"error": "forbidden"})
        with caplog.at_level(logging.WARNING):
            identity = await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

        assert identity.subject == "ms-sub-1"
        assert identity.email == "user@contoso.com"
        assert identity.tenancies == ()
        assert identity.domain_owning_tenancies() == ()
        # The consumer-facing gate refuses the user's own email domain:
        # degrading withholds the assertion rather than fabricating it.
        assert identity.owns_domain("contoso.com") is False
        assert "could not resolve the tenant's verified domains" in caplog.text
        assert "access-abc" not in caplog.text

    async def test_transport_error_degrades_to_no_tenancy(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_exception(httpx.ConnectError("boom"), url=_ORGANIZATION_URL)
        with caplog.at_level(logging.WARNING):
            identity = await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

        assert identity.subject == "ms-sub-1"
        assert identity.tenancies == ()
        assert "could not resolve the tenant's verified domains" in caplog.text
        assert "network error" in caplog.text
        assert "ConnectError" not in caplog.text

    async def test_non_json_degrades_to_no_tenancy(self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, status_code=200, content=b"not-json")
        with caplog.at_level(logging.WARNING):
            identity = await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

        assert identity.subject == "ms-sub-1"
        assert identity.tenancies == ()
        assert "could not parse the tenant's verified domains" in caplog.text

    async def test_deeply_nested_degrades_to_no_tenancy(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A body that nests too deeply to decode degrades like any other unreadable body."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, status_code=200, content=b"[" * 100_000 + b"]" * 100_000)
        with caplog.at_level(logging.WARNING):
            identity = await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

        assert identity.subject == "ms-sub-1"
        assert identity.tenancies == ()
        assert "could not parse the tenant's verified domains" in caplog.text

    async def test_empty_collection_degrades_to_no_tenancy(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ):
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json={"value": []})
        with caplog.at_level(logging.WARNING):
            identity = await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

        assert identity.subject == "ms-sub-1"
        assert identity.tenancies == ()
        assert "returned no organization" in caplog.text


class TestMicrosoftIdTokenVerification:
    """Test that the ID token is trusted only after its signature and claims check out."""

    async def test_refuses_a_forged_id_token_before_any_graph_call(self, httpx_mock: HTTPXMock) -> None:
        """A token signed by a key Microsoft does not publish never reaches Graph."""
        forged = _member_id_token(key=jwk.RSAKey.generate_key(2048))

        with pytest.raises(IdentityFetchError, match="signature did not verify"):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=forged), _config()
            )

        assert [str(request.url) for request in httpx_mock.get_requests()] == [_KEYS_URL]

    @pytest.mark.parametrize(
        ("claims", "message"),
        [
            ({"aud": "another-client"}, "invalid aud claim"),
            ({"aud": [_CLIENT_ID, "another-client"]}, "invalid aud claim"),
            ({"iss": "https://login.microsoftonline.com/other-tenant/v2.0"}, "invalid iss claim"),
            ({"exp": int(time.time()) - 3600}, "has expired"),
            ({"nbf": int(time.time()) + 3600}, "invalid nbf claim"),
            ({"sub": ""}, "invalid sub claim"),
            ({"exp": _OMIT}, "missing the exp claim"),
            ({"iat": _OMIT}, "missing the iat claim"),
            ({"exp": None}, "missing the exp claim"),
            ({"exp": _OMIT, "iat": _OMIT}, "missing the exp, iat claims"),
        ],
    )
    async def test_refuses_an_id_token_with_bad_claims(self, claims: dict[str, object], message: str) -> None:
        """A signed token issued for another client, outside its lifetime, or without a subject is refused."""
        with pytest.raises(TokenValidationError, match=message) as exc_info:
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token(**claims)), _config()
            )
        if "expired" in message:
            expected = TokenValidationReason.EXPIRED
        elif "aud" in message:
            expected = TokenValidationReason.AUDIENCE
        elif "iss claim" in message:
            expected = TokenValidationReason.UNKNOWN_ISSUER
        else:
            expected = TokenValidationReason.CLAIMS
        assert exc_info.value.reason is expected

    async def test_refuses_an_expired_id_token_as_expired(self) -> None:
        """An expired token raises its own refusal, so the caller can tell it from a forged one."""
        with pytest.raises(TokenExpiredError) as exc_info:
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token(exp=int(time.time()) - 3600)),
                _config(),
            )
        assert exc_info.value.reason is TokenValidationReason.EXPIRED

    @pytest.mark.parametrize(
        ("userinfo_sub", "message"), [("someone-else", "a different subject"), (None, "names no subject")]
    )
    async def test_refuses_a_userinfo_subject_that_does_not_match(
        self, httpx_mock: HTTPXMock, userinfo_sub: str | None, message: str
    ) -> None:
        """OpenID Connect Core 1.0 section 5.3.2 requires userinfo to name the ID token's subject."""
        userinfo = {name: value for name, value in _USERINFO.items() if name != "sub"}
        if userinfo_sub is not None:
            userinfo["sub"] = userinfo_sub
        httpx_mock.add_response(url=_USERINFO_URL, json=userinfo)

        with pytest.raises(IdentityFetchError, match=message):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

    async def test_the_client_keeps_the_handler_it_built(self, httpx_mock: HTTPXMock) -> None:
        """Two sign-ins through one client fetch Microsoft's key set once."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO, is_reusable=True)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"]), is_reusable=True)
        client = OAuthClient(_config())
        tokens = FreshTokenSet(access_token="access-abc", metadata={"id_token": _member_id_token()})

        await client.fetch_identity(tokens)
        await client.fetch_identity(tokens)

        assert [str(request.url) for request in httpx_mock.get_requests()].count(_KEYS_URL) == 1

    @pytest.mark.parametrize(
        "bad_tid",
        ["not-a-guid", "1234", "11111111222233334444555555555555", 12345, "", None],
    )
    async def test_non_guid_tid_is_refused(self, bad_tid: object) -> None:
        """Without a tenant GUID the issuer cannot be checked, so the token is refused."""
        id_token = _fake_jwt({"tid": bad_tid, "iss": _ISSUER, "sub": "ms-sub-1"})
        with pytest.raises(IdentityFetchError, match="invalid tid claim"):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
            )

    async def test_issuer_not_bound_to_tid_is_refused(self) -> None:
        """``iss`` must equal ``.../{tid}/v2.0``, so an issuer naming another tenant is refused."""
        id_token = _member_id_token(iss="https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0")
        with pytest.raises(IdentityFetchError, match="invalid iss claim"):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=id_token), _config()
            )

    @pytest.mark.parametrize(
        "malformed",
        [
            "single-segment-token",
            "header-only.",
            "header.!!!not-valid-base64!!!.sig",
            "header.eyJ0aWQ.sig",  # A truncated payload.
            "header.aGVsbG8.sig",  # It decodes to "hello", not JSON.
        ],
    )
    async def test_malformed_id_token_is_refused(self, httpx_mock: HTTPXMock, malformed: str) -> None:
        """A malformed ID token stops the sign-in before any Graph call, as it does for any OpenID provider."""
        with pytest.raises(IdentityFetchError, match="not a compact signed token"):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=malformed), _config()
            )

        assert _USERINFO_URL not in [str(request.url) for request in httpx_mock.get_requests()]

    async def test_an_empty_id_token_is_treated_as_absent(self, httpx_mock: HTTPXMock) -> None:
        """An empty ID token carries nothing to verify, so identity comes from userinfo, as for any OpenID provider."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=""), _config()
        )

        assert identity.subject == "ms-sub-1"
        assert identity.tenancies == ()

    async def test_accepts_an_uppercase_client_id(self, httpx_mock: HTTPXMock) -> None:
        """Entra app IDs are GUIDs, so a client ID configured in uppercase still matches the token's ``aud``."""
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"]))
        app_id = "8a1b2c3d-0000-4000-8000-abcdef012345"
        config, _ = preset(client_id=app_id.upper(), client_secret="msecret", scopes=["openid"])

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token(aud=app_id)), config
        )

        assert identity.subject == "ms-sub-1"

    @pytest.mark.parametrize(
        "key_issuer",
        ["https://login.microsoftonline.com/{tenantid}/v2.0", f"https://login.microsoftonline.com/{_TENANT_ID}/v2.0"],
    )
    async def test_accepts_a_key_whose_issuer_matches_the_token(self, httpx_mock: HTTPXMock, key_issuer: str) -> None:
        """A key that names its issuer, with or without the tenant placeholder, verifies its own tenant's tokens."""
        httpx_mock.reset()
        published = _SIGNING_KEY.as_dict(private=False) | {"issuer": key_issuer}
        httpx_mock.add_response(url=_KEYS_URL, json={"keys": [published]})
        httpx_mock.add_response(url=_USERINFO_URL, json=_USERINFO)
        httpx_mock.add_response(url=_ORGANIZATION_URL, json=_org_response(["contoso.com"]))

        identity = await MicrosoftIdentityHandler().fetch_identity(
            IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
        )

        assert identity.subject == "ms-sub-1"

    async def test_refuses_a_key_that_belongs_to_another_issuer(self, httpx_mock: HTTPXMock) -> None:
        """A key published for one issuer never vouches for another tenant's token."""
        httpx_mock.reset()
        other = "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0"
        httpx_mock.add_response(url=_KEYS_URL, json={"keys": [_SIGNING_KEY.as_dict(private=False) | {"issuer": other}]})

        with pytest.raises(IdentityFetchError, match="signing key belongs to another issuer"):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=_member_id_token()), _config()
            )

    async def test_refuses_an_algorithm_microsoft_does_not_use(self) -> None:
        """Microsoft signs ID tokens with RS256 only, so a token signed by its key with another algorithm is refused."""
        claims = {"tid": _TENANT_ID, "iss": _ISSUER, "sub": "ms-sub-1", "aud": _CLIENT_ID}
        claims |= {"exp": int(time.time()) + 300, "iat": int(time.time())}
        token = jws.serialize_compact(
            {"alg": "PS256", "kid": "ms-key-1"}, json.dumps(claims).encode(), _SIGNING_KEY, algorithms=["PS256"]
        )

        with pytest.raises(IdentityFetchError, match="signing algorithm"):
            await MicrosoftIdentityHandler().fetch_identity(
                IdentityMaterial(access_token="access-abc", id_token=token), _config()
            )
