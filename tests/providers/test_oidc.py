from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from typing import Any

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import ConfigurationError, IdentityFetchError, OidcDiscoveryError
from apron_auth.models import IdentityMaterial, ProviderConfig, ServerMetadata, TokenEndpointAuthMethod
from apron_auth.protocols import StandardRevocationHandler
from apron_auth.providers.oidc import (
    OidcIdentityHandler,
    discover,
    discovery_url,
    identity_handler,
    preset,
)

ISSUER = "https://sso.example.com/realms/acme"
DOCUMENT_URL = f"{ISSUER}/.well-known/openid-configuration"
AUTHORIZE_URL = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
USERINFO_URL = f"{ISSUER}/protocol/openid-connect/userinfo"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
CLIENT_ID = "otari"


def document(**overrides: Any) -> dict[str, Any]:
    """A minimal-but-realistic OpenID provider configuration document."""
    base = {
        "issuer": ISSUER,
        "authorization_endpoint": AUTHORIZE_URL,
        "token_endpoint": TOKEN_URL,
        "userinfo_endpoint": USERINFO_URL,
        "jwks_uri": JWKS_URL,
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
    }
    base.update(overrides)
    return base


def _b64(raw: bytes) -> str:
    """Unpadded base64url, the encoding every JWS segment uses."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _at_hash(access_token: str) -> str:
    """The ``at_hash`` a token carrying one would assert for ``access_token``.

    ``validate_at_hash`` hashes the access token with the header's algorithm
    and takes the left half (OpenID Connect Core 1.0, section 3.1.3.7 step 8);
    for the ``RS256`` header every token in this file uses, that is SHA-256.
    """
    digest = hashlib.sha256(access_token.encode()).digest()
    return _b64(digest[:16])


def id_token(**claims: Any) -> str:
    """An unsigned JWT carrying ``claims``, shaped like a real one.

    The signature is never checked (see the module docstring), so a placeholder
    third segment is what a provider's token would be indistinguishable from
    here. The *header* is real, though: extraction parses it, so a placeholder
    there would make every token in this file unparseable rather than
    unsigned.

    Every claim section 2 makes REQUIRED — ``iss``, ``sub``, ``aud``, ``exp``,
    ``iat`` — is set by default, so a token is valid unless a test deliberately
    breaks one. Pass ``_OMIT`` for a claim to drop it.
    """
    now = int(time.time())
    payload = {"iss": ISSUER, "sub": "u-1", "aud": CLIENT_ID, "exp": now + 300, "iat": now, **claims}
    payload = {key: value for key, value in payload.items() if value is not _OMIT}
    return f"{_b64(json.dumps({'alg': 'RS256'}).encode())}.{_b64(json.dumps(payload).encode())}.signature"


_OMIT = object()
"""Sentinel letting a test drop a claim the helper otherwise always sets."""


async def _userinfo_app(scope: Any, receive: Any, send: Any) -> None:
    """A minimal ASGI userinfo endpoint, to prove a transport factory is honored."""
    del scope, receive
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": json.dumps({"sub": "u-1"}).encode()})


def metadata(**overrides: Any) -> ServerMetadata:
    base: dict[str, Any] = {
        "authorize_url": AUTHORIZE_URL,
        "token_url": TOKEN_URL,
        "userinfo_url": USERINFO_URL,
        "jwks_url": JWKS_URL,
        "issuer": ISSUER,
    }
    base.update(overrides)
    return ServerMetadata(**base)


class TestDiscoveryUrl:
    def test_appends_the_well_known_suffix_to_the_issuer_path(self):
        assert discovery_url(ISSUER) == DOCUMENT_URL

    def test_preserves_a_realm_path_rather_than_resolving_against_the_root(self):
        """A root-absolute join would drop ``/realms/acme`` and probe the host root."""
        assert discovery_url("https://sso.example.com/realms/acme").startswith("https://sso.example.com/realms/acme/")

    def test_tolerates_a_trailing_slash_on_the_issuer(self):
        assert discovery_url(f"{ISSUER}/") == DOCUMENT_URL

    def test_handles_an_issuer_at_the_host_root(self):
        assert discovery_url("https://sso.example.com") == "https://sso.example.com/.well-known/openid-configuration"

    def test_refuses_an_issuer_that_is_not_an_absolute_url(self):
        """A bare hostname is not a URL, and neither is a path or a fragment.

        ``urlparse`` accepts all of these without complaint — its only failure
        mode is an unterminated IPv6 literal — so the guard has to check the
        parsed shape, or the malformed issuer would surface later as a
        malformed *URL* and lose which input was at fault.
        """
        for issuer in ("example.com", "/realms/acme", "https://"):
            with pytest.raises(OidcDiscoveryError, match="not an absolute URL"):
                discovery_url(issuer)


class TestDiscover:
    async def test_reads_every_endpoint_from_the_document(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=DOCUMENT_URL, json=document())

        discovered = await discover(ISSUER)

        assert discovered.authorize_url == AUTHORIZE_URL
        assert discovered.token_url == TOKEN_URL
        assert discovered.userinfo_url == USERINFO_URL
        assert discovered.jwks_url == JWKS_URL
        assert discovered.issuer == ISSUER
        assert discovered.code_challenge_methods == ["S256"]

    async def test_refuses_a_document_naming_a_different_issuer(self, httpx_mock: HTTPXMock):
        """OpenID Connect Discovery 1.0 section 4.3: the two must match.

        Without this the issuer is not a trust anchor at all, because every
        later ``iss`` check would measure against whatever the document said.
        """
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(issuer="https://attacker.example"))

        with pytest.raises(OidcDiscoveryError, match="different issuer"):
            await discover(ISSUER)

    async def test_refuses_a_document_that_differs_only_by_a_trailing_slash(self, httpx_mock: HTTPXMock):
        """Two issuers differing by a slash are two different strings downstream."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(issuer=f"{ISSUER}/"))

        with pytest.raises(OidcDiscoveryError, match="different issuer"):
            await discover(ISSUER)

    async def test_refuses_a_document_declaring_no_issuer(self, httpx_mock: HTTPXMock):
        payload = document()
        del payload["issuer"]
        httpx_mock.add_response(url=DOCUMENT_URL, json=payload)

        with pytest.raises(OidcDiscoveryError, match="declares no issuer"):
            await discover(ISSUER)

    async def test_refuses_a_document_missing_an_endpoint(self, httpx_mock: HTTPXMock):
        payload = document()
        del payload["token_endpoint"]
        httpx_mock.add_response(url=DOCUMENT_URL, json=payload)

        with pytest.raises(OidcDiscoveryError, match="missing an endpoint"):
            await discover(ISSUER)

    async def test_reports_a_non_200_document(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=DOCUMENT_URL, status_code=404)

        with pytest.raises(OidcDiscoveryError, match="HTTP 404"):
            await discover(ISSUER)

    async def test_logs_a_warning_when_the_document_redirects(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ):
        """Redirects are not followed, so a CDN-fronted provider fails.

        The failure is still an error, but the warning names the redirect
        target so an operator knows the provider is alive and where it moved —
        the actionable half of an otherwise opaque HTTP 301.
        """
        httpx_mock.add_response(
            url=DOCUMENT_URL,
            status_code=301,
            headers={"location": "https://sso.example.com/realms/acme/.well-known/openid-configuration"},
        )

        with (
            caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"),
            pytest.raises(OidcDiscoveryError, match="HTTP 301"),
        ):
            await discover(ISSUER)

        assert "HTTP 301" in caplog.text
        assert "openid-configuration" in caplog.text

    async def test_reports_a_non_json_document(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=DOCUMENT_URL, text="not json")

        with pytest.raises(OidcDiscoveryError, match="not JSON"):
            await discover(ISSUER)

    async def test_honors_a_document_url_override(self, httpx_mock: HTTPXMock):
        override = "https://sso.example.com/nonstandard-config"
        httpx_mock.add_response(url=override, json=document())

        discovered = await discover(ISSUER, document_url=override)

        assert discovered.issuer == ISSUER

    async def test_an_override_does_not_loosen_the_issuer_check(self, httpx_mock: HTTPXMock):
        override = "https://sso.example.com/nonstandard-config"
        httpx_mock.add_response(url=override, json=document(issuer="https://attacker.example"))

        with pytest.raises(OidcDiscoveryError, match="different issuer"):
            await discover(ISSUER, document_url=override)

    async def test_reports_a_malformed_issuer(self):
        """``urlparse`` rejects an unterminated IPv6 literal before any URL is built.

        The bare ``ValueError`` it raises would otherwise escape ``discover``,
        which documents ``OidcDiscoveryError`` for every bad input.
        """
        with pytest.raises(OidcDiscoveryError, match="malformed issuer"):
            await discover("https://[::1")

    async def test_reports_a_malformed_document_url_override(self):
        """The override skips ``discovery_url``, so httpx is what rejects it.

        ``httpx.InvalidURL`` is not a ``RequestError``, so without being caught
        alongside them it would escape as an httpx exception rather than the
        ``OidcDiscoveryError`` this module documents for every bad input.
        """
        with pytest.raises(OidcDiscoveryError, match="could not fetch"):
            await discover(ISSUER, document_url="https://[::1")

    async def test_reports_an_unreachable_document(self, httpx_mock: HTTPXMock):
        httpx_mock.add_exception(httpx.ConnectError("no route"), url=DOCUMENT_URL)

        with pytest.raises(OidcDiscoveryError, match="could not fetch"):
            await discover(ISSUER)

    async def test_reports_a_document_that_is_json_but_not_an_object(self, httpx_mock: HTTPXMock):
        """Valid JSON, wrong shape — distinct from a body that will not parse at all."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=["not", "a", "document"])

        with pytest.raises(OidcDiscoveryError, match="not a JSON object"):
            await discover(ISSUER)

    async def test_ignores_a_list_valued_field_that_is_not_a_list(self, httpx_mock: HTTPXMock):
        """A provider sending a bare string where an array belongs yields no entries.

        Dropped rather than coerced: a single-element list built from a string
        would be a value this library invented, not one the provider advertised.
        """
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(scopes_supported="openid"))

        assert (await discover(ISSUER)).scopes_supported == []


class TestPreset:
    def test_builds_a_config_from_discovered_metadata(self):
        config, revocation = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=["email", "profile"],
            metadata=metadata(),
        )

        assert config.authorize_url == AUTHORIZE_URL
        assert config.token_url == TOKEN_URL
        assert config.issuer == ISSUER
        assert revocation is None

    def test_merges_the_openid_scope(self):
        """Without it the provider runs a plain OAuth flow and returns no ID token."""
        config, _ = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=["email"],
            metadata=metadata(),
        )

        assert "openid" in config.scopes

    def test_pairs_a_revocation_handler_when_the_provider_advertises_one(self):
        _, revocation = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=[],
            metadata=metadata(revocation_url=f"{ISSUER}/protocol/openid-connect/revoke"),
        )

        assert isinstance(revocation, StandardRevocationHandler)

    def test_carries_iss_support_onto_the_config(self):
        config, _ = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=[],
            metadata=metadata(iss_parameter_supported=True),
        )

        assert config.require_iss is True

    def test_enables_pkce_when_the_provider_advertises_s256(self):
        config, _ = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=[],
            metadata=metadata(code_challenge_methods=["S256"]),
        )

        assert config.use_pkce is True

    def test_enables_pkce_when_the_provider_advertises_nothing(self):
        """A provider that does not implement PKCE ignores the extra parameters."""
        config, _ = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=[],
            metadata=metadata(code_challenge_methods=[]),
        )

        assert config.use_pkce is True

    @pytest.mark.parametrize("methods", [["plain"], ["S384"], ["plain", "S512"]])
    def test_refuses_a_provider_advertising_no_s256_method(self, methods: list[str]):
        """Refused, not silently configured without PKCE.

        ``OAuthClient`` issues only ``S256``, so PKCE cannot be negotiated with
        such a provider. Clearing ``use_pkce`` instead would return a config
        with *no* code-injection defense, because this module also sends no
        ``nonce`` — PKCE is the only thing binding the code to the session.
        Failing at config time is the same posture ``_select_auth_method``
        takes for an unperformable token-endpoint auth method.
        """
        with pytest.raises(ConfigurationError, match="no S256 code-challenge method"):
            preset(
                client_id=CLIENT_ID,
                client_secret="s3cret",
                scopes=[],
                metadata=metadata(code_challenge_methods=methods),
            )

    def test_keeps_pkce_when_s256_appears_alongside_others(self):
        config, _ = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=[],
            metadata=metadata(code_challenge_methods=["plain", "S256"]),
        )

        assert config.use_pkce is True

    def test_prefers_client_secret_post_among_advertised_methods(self):
        config, _ = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=[],
            metadata=metadata(token_endpoint_auth_methods=["client_secret_basic", "client_secret_post"]),
        )

        assert config.token_endpoint_auth_method == TokenEndpointAuthMethod.CLIENT_SECRET_POST

    def test_falls_back_to_basic_when_that_is_all_that_is_advertised(self):
        config, _ = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=[],
            metadata=metadata(token_endpoint_auth_methods=["client_secret_basic"]),
        )

        assert config.token_endpoint_auth_method == TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

    def test_refuses_a_provider_offering_only_unperformable_methods(self):
        with pytest.raises(ConfigurationError, match="no token-endpoint auth method"):
            preset(
                client_id=CLIENT_ID,
                client_secret="s3cret",
                scopes=[],
                metadata=metadata(token_endpoint_auth_methods=["private_key_jwt"]),
            )

    def test_refuses_metadata_naming_no_issuer(self):
        """An issuer-less config would silently skip every ``iss`` check.

        ``identity_handler`` refuses the same input; the two factories must
        agree, because a config that never validates ``iss`` has no trust
        anchor at all.
        """
        with pytest.raises(ConfigurationError, match="names no issuer"):
            preset(
                client_id=CLIENT_ID,
                client_secret="s3cret",
                scopes=[],
                metadata=metadata(issuer=None),
            )

    def test_asserts_no_domain_ownership(self):
        """OpenID Connect standardizes no domain-ownership claim."""
        config, _ = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=[],
            metadata=metadata(),
        )

        assert config.can_assert_domain_ownership is False

    def test_adds_no_extra_params_of_its_own(self):
        config, _ = preset(
            client_id=CLIENT_ID,
            client_secret="s3cret",
            scopes=[],
            metadata=metadata(),
        )

        assert config.extra_params == {}


class TestIdentityHandlerFactory:
    def test_builds_a_handler_from_metadata(self):
        assert isinstance(identity_handler(metadata(), client_id=CLIENT_ID), OidcIdentityHandler)

    def test_refuses_metadata_naming_no_issuer(self):
        """Section 3.1.3.7 step 2 makes the ``iss`` comparison a MUST.

        An issuer-less handler would construct fine and then silently skip it,
        so the refusal happens here rather than becoming a per-token no-op.
        """
        with pytest.raises(OidcDiscoveryError, match="names no issuer"):
            identity_handler(metadata(issuer=None), client_id=CLIENT_ID)

    def test_builds_a_handler_without_a_userinfo_endpoint(self):
        """Identity can rest on the ID token alone; the issuer is what cannot be missing."""
        assert isinstance(identity_handler(metadata(userinfo_url=None), client_id=CLIENT_ID), OidcIdentityHandler)


class TestOidcIdentity:
    @pytest.fixture
    def handler(self) -> OidcIdentityHandler:
        return identity_handler(metadata(), client_id=CLIENT_ID)

    @pytest.fixture
    def config(self) -> ProviderConfig:
        built, _ = preset(client_id=CLIENT_ID, client_secret="s3cret", scopes=[], metadata=metadata())
        return built

    async def test_reads_identity_from_userinfo_and_the_id_token(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(
            url=USERINFO_URL,
            json={
                "sub": "u-1",
                "email": "person@acme.com",
                "name": "A Person",
                "picture": "https://acme.com/a.png",
                "preferred_username": "aperson",
            },
        )

        identity = await handler.fetch_identity(
            IdentityMaterial(
                access_token="access",
                id_token=id_token(sub="u-1", email="person@acme.com", email_verified=True, groups=["staff"]),
            ),
            config,
        )

        assert identity.provider == f"oidc:{ISSUER}"
        assert identity.subject == "u-1"
        assert identity.email == "person@acme.com"
        assert identity.email_verified is True
        assert identity.name == "A Person"
        assert identity.username == "aperson"
        assert identity.tenancies == ()
        assert identity.raw == {
            "id_token": {
                "iss": ISSUER,
                "sub": "u-1",
                "aud": CLIENT_ID,
                "exp": pytest.approx(time.time() + 300, abs=5),
                "iat": pytest.approx(time.time(), abs=5),
                "email": "person@acme.com",
                "email_verified": True,
                "groups": ["staff"],
            },
            "userinfo": {
                "sub": "u-1",
                "email": "person@acme.com",
                "name": "A Person",
                "picture": "https://acme.com/a.png",
                "preferred_username": "aperson",
            },
        }

    async def test_works_without_an_id_token(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1", "email": "person@acme.com"})

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

        assert identity.subject == "u-1"
        assert identity.email_verified is None

    async def test_works_without_a_userinfo_endpoint(self, config: ProviderConfig):
        """A provider advertising none still identifies someone via the ID token."""
        handler = identity_handler(metadata(userinfo_url=None), client_id=CLIENT_ID)

        identity = await handler.fetch_identity(
            IdentityMaterial(
                access_token="access",
                id_token=id_token(sub="u-1", email="person@acme.com", email_verified=True),
            ),
            config,
        )

        assert identity.subject == "u-1"
        assert identity.email == "person@acme.com"

    async def test_prefers_the_id_token_email_verified_claim(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """The trust-bearing document wins on the claim an access decision rests on."""
        httpx_mock.add_response(
            url=USERINFO_URL, json={"sub": "u-1", "email": "person@acme.com", "email_verified": True}
        )

        identity = await handler.fetch_identity(
            IdentityMaterial(
                access_token="access",
                id_token=id_token(sub="u-1", email="person@acme.com", email_verified=False),
            ),
            config,
        )

        assert identity.email == "person@acme.com"
        assert identity.email_verified is False

    async def test_reports_a_non_boolean_email_verified_as_unasserted(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """A bare bool() would read the string "false" as True."""
        httpx_mock.add_response(
            url=USERINFO_URL, json={"sub": "u-1", "email": "person@acme.com", "email_verified": "false"}
        )

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

        assert identity.email_verified is None

    async def test_refuses_an_id_token_from_another_issuer(self, handler: OidcIdentityHandler, config: ProviderConfig):
        with pytest.raises(IdentityFetchError, match=r"Invalid claim: 'iss'"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(iss="https://attacker.example")),
                config,
            )

    async def test_refuses_an_id_token_minted_for_another_client(
        self, handler: OidcIdentityHandler, config: ProviderConfig
    ):
        with pytest.raises(IdentityFetchError, match=r"Invalid claim: 'aud'"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(aud="someone-else")),
                config,
            )

    async def test_accepts_an_audience_array_naming_this_client(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})

        identity = await handler.fetch_identity(
            IdentityMaterial(
                access_token="access", id_token=id_token(sub="u-1", aud=["other", CLIENT_ID], azp=CLIENT_ID)
            ),
            config,
        )

        assert identity.subject == "u-1"

    async def test_refuses_an_expired_id_token(self, handler: OidcIdentityHandler, config: ProviderConfig):
        with pytest.raises(IdentityFetchError, match=r"token is expired"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(exp=time.time() - 3600)),
                config,
            )

    async def test_tolerates_clock_skew_within_the_leeway(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})

        identity = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", exp=time.time() - 30)),
            config,
        )

        assert identity.subject == "u-1"

    @pytest.mark.parametrize("claim", ["exp", "iat", "sub", "aud", "iss"])
    async def test_refuses_an_id_token_missing_an_essential_claim(
        self, handler: OidcIdentityHandler, config: ProviderConfig, claim: str
    ):
        """Section 2 makes ``iss``, ``sub``, ``aud``, ``exp`` and ``iat`` REQUIRED.

        ``iat`` is the one our hand-rolled validation never checked; it comes
        for free with authlib's essential-claims set.
        """
        with pytest.raises(IdentityFetchError, match=rf"Missing claim: '{claim}'"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(**{claim: _OMIT})),
                config,
            )

    async def test_refuses_a_userinfo_subject_that_disagrees_with_the_id_token(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """OpenID Connect Core 1.0 section 5.3.2 — not a field to prefer between."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "someone-else"})

        with pytest.raises(IdentityFetchError, match="different subject"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1")),
                config,
            )

    async def test_falls_back_to_userinfo_when_the_id_token_is_unparseable(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """A provider returning junk has still authenticated somebody."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1", "email": "person@acme.com"})

        identity = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token="not-a-jwt"),
            config,
        )

        assert identity.subject == "u-1"

    async def test_refuses_when_neither_document_yields_a_subject(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(url=USERINFO_URL, json={"email": "person@acme.com"})

        with pytest.raises(IdentityFetchError, match="no subject"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    async def test_reports_a_failed_userinfo_request(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(url=USERINFO_URL, status_code=401)

        with pytest.raises(IdentityFetchError, match="Failed to fetch"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    async def test_reports_a_non_object_userinfo_response(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(url=USERINFO_URL, json=["not", "an", "object"])

        with pytest.raises(IdentityFetchError, match="not a JSON object"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    async def test_refuses_a_multi_audience_token_without_azp(
        self, handler: OidcIdentityHandler, config: ProviderConfig
    ):
        """Section 3.1.3.7 step 4 — ``aud`` arrays are accepted, so the condition is reachable."""
        with pytest.raises(IdentityFetchError, match=r"Missing claim: 'azp'"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", aud=["other", CLIENT_ID])),
                config,
            )

    async def test_refuses_a_token_authorized_for_another_client(
        self, handler: OidcIdentityHandler, config: ProviderConfig
    ):
        """Section 3.1.3.7 step 5.

        ``aud`` names this client, so the audience check alone passes; ``azp``
        is what says the token was actually minted for somebody else.
        """
        with pytest.raises(IdentityFetchError, match=r"claim: 'azp'"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", azp="someone-else")),
                config,
            )

    async def test_accepts_a_single_audience_token_carrying_a_matching_azp(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})

        identity = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", azp=CLIENT_ID)),
            config,
        )

        assert identity.subject == "u-1"

    async def test_accepts_an_at_hash_matching_the_access_token(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """Section 3.1.3.7 step 8 — the token was minted over *this* access token."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})

        identity = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", at_hash=_at_hash("access"))),
            config,
        )

        assert identity.subject == "u-1"

    async def test_refuses_an_at_hash_for_another_access_token(
        self, handler: OidcIdentityHandler, config: ProviderConfig
    ):
        """The hash binds the ID token to a specific access token.

        The material carries one access token and the token asserts a hash over
        a different one — a token minted for a different request, which the
        bearer must not be able to use.
        """
        with pytest.raises(IdentityFetchError, match=r"claim: 'at_hash'"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", at_hash=_at_hash("other"))),
                config,
            )

    async def test_never_pairs_an_email_with_another_documents_verification(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """The two fields are one assertion and must come from one document.

        The ID token asserts an address but never says it verified it; userinfo
        verified a *different* address. Crossing them would let
        ``verified_email()`` return an address nothing vouched for.
        """
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1", "email": "real@acme.com", "email_verified": True})

        identity = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", email="other@acme.com")),
            config,
        )

        assert identity.email == "other@acme.com"
        assert identity.email_verified is None
        assert identity.verified_email() is None

    async def test_drops_a_verification_flag_with_no_address_beside_it(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1", "email_verified": True})

        identity = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token=id_token(sub="u-1")),
            config,
        )

        assert identity.email is None
        assert identity.email_verified is None

    async def test_refuses_an_id_token_with_no_subject(self, handler: OidcIdentityHandler, config: ProviderConfig):
        """``sub`` is REQUIRED (section 2), so a token without one is malformed.

        Reported as such rather than as the subject disagreement the userinfo
        cross-check below would otherwise raise.
        """
        with pytest.raises(IdentityFetchError, match=r"Missing claim: 'sub'"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub=_OMIT)),
                config,
            )

    async def test_namespaces_the_provider_by_issuer(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """``identity_key`` must not collide between two generic connections.

        A ``sub`` is unique only within an issuer (section 2), so a bare
        ``"oidc"`` would let any ``sub`` one issuer mints collide with the
        other's user records.
        """
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})
        other = OidcIdentityHandler(userinfo_url=None, issuer="https://sso.other.example", client_id=CLIENT_ID)

        mine = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token=id_token(sub="u-1")), config
        )
        theirs = await other.fetch_identity(
            IdentityMaterial(
                access_token="access",
                id_token=id_token(sub="u-1", iss="https://sso.other.example"),
            ),
            config,
        )

        assert mine.identity_key() != theirs.identity_key()

    async def test_routes_the_userinfo_request_through_a_transport_factory(self, config: ProviderConfig):
        """The factory ``discover`` accepts must also cover the one other outbound call."""
        seen: list[str] = []

        def factory(url: str) -> httpx.AsyncBaseTransport:
            seen.append(url)
            return httpx.ASGITransport(app=_userinfo_app)

        handler = identity_handler(metadata(), client_id=CLIENT_ID, transport_factory=factory)

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

        assert seen == [USERINFO_URL]
        assert identity.subject == "u-1"

    async def test_reports_an_unparseable_userinfo_body(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """HTTP 200 with a body that is not JSON at all — distinct from wrong-shaped JSON."""
        httpx_mock.add_response(url=USERINFO_URL, status_code=200, content=b"<html>nope</html>")

        with pytest.raises(IdentityFetchError, match="Failed to parse"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    @pytest.mark.parametrize(
        ("payload", "reason"),
        [
            ("", "an empty payload segment"),
            ("!!!not-base64!!!", "a payload segment that will not decode"),
            (_b64(b"{not json"), "a payload that is not JSON"),
            (_b64(b'["a","list"]'), "a payload that is not an object"),
        ],
    )
    async def test_degrades_to_userinfo_for_a_junk_payload_segment(
        self,
        handler: OidcIdentityHandler,
        config: ProviderConfig,
        httpx_mock: HTTPXMock,
        payload: str,
        reason: str,
    ):
        """Three shapes of junk, all reached past the JWT-shape check.

        The existing "not-a-jwt" case is refused on segment count before any
        decoding happens, so it never exercises these. A provider returning
        junk has still authenticated somebody: userinfo says who.
        """
        del reason
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1", "email": "person@acme.com"})
        header = _b64(json.dumps({"alg": "RS256"}).encode())

        identity = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token=f"{header}.{payload}.sig"),
            config,
        )

        assert identity.subject == "u-1"
        assert identity.raw["id_token"] == {}

    @pytest.mark.parametrize("audience", [42, {"aud": "otari"}, ["other"], []])
    async def test_refuses_an_id_token_whose_audience_is_not_a_string_or_array(
        self, handler: OidcIdentityHandler, config: ProviderConfig, audience: object
    ):
        """``aud`` is a string or an array of strings naming us (section 2).

        An oddly-typed ``aud``, or an array that does not name this client,
        must fail closed rather than being treated as "no audience to disagree
        with".
        """
        with pytest.raises(IdentityFetchError, match=r"claim: 'a(ud|zp)'"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", aud=audience)),
                config,
            )

    async def test_refuses_a_non_string_azp(self, handler: OidcIdentityHandler, config: ProviderConfig):
        """A present-but-untyped ``azp`` is a claim that cannot be checked, so it fails closed."""
        with pytest.raises(IdentityFetchError, match=r"claim: 'azp'"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", azp=42)),
                config,
            )

    async def test_the_issuer_check_cannot_be_disabled(self, config: ProviderConfig):
        """``issuer`` is a required constructor argument, so there is no un-checked mode."""
        with pytest.raises(TypeError):
            OidcIdentityHandler(userinfo_url=USERINFO_URL, client_id=CLIENT_ID)  # type: ignore[call-arg]
