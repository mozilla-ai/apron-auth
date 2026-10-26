from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
import traceback
from typing import Any

import httpx
import pytest
from joserfc import jwk, jws
from pytest_httpx import HTTPXMock

from apron_auth._discovery import IssuerNotDeclaredError
from apron_auth.client import OAuthClient
from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    IdentityNotSupportedError,
    IdentityScopeNotGrantedError,
    OidcDiscoveryError,
    TokenExpiredError,
    TokenValidationError,
    TokenValidationReason,
)
from apron_auth.models import (
    FreshTokenSet,
    IdentityMaterial,
    ProviderConfig,
    ServerMetadata,
    TokenEndpointAuthMethod,
    UrlField,
)
from apron_auth.providers.oidc import (
    OidcIdentityHandler,
    _bearer_error,
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
CLIENT_SECRET = "s3cret"  # pragma: allowlist secret
# Codes that differ from ``insufficient_scope`` by a prefix, a suffix, padding or letter case.
NEAR_MISS_SCOPE_CODES = ("x_insufficient_scope", "insufficient_scope_v2", " insufficient_scope", "Insufficient_Scope")


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


RSA_KEY = jwk.RSAKey.generate_key(2048, parameters={"kid": "rsa-1"})
OKP_KEY = jwk.OKPKey.generate_key("Ed25519", parameters={"kid": "okp-1"})
PUBLISHED_KEYS = {"keys": [RSA_KEY.as_dict(private=False), OKP_KEY.as_dict(private=False)]}
_KEY_FOR_ALG = {"EdDSA": OKP_KEY, "RS256": RSA_KEY}


def id_token(*, alg: str = "RS256", key: Any = None, **claims: Any) -> str:
    """Return an ID token signed with the issuer's published key for ``alg``, carrying ``claims``.

    Every claim section 2 makes REQUIRED is set by default, so a token is valid unless a test breaks one.
    Pass ``_OMIT`` for a claim to drop it, and ``key`` to sign with a key the issuer does not publish.
    """
    now = int(time.time())
    payload = {"iss": ISSUER, "sub": "u-1", "aud": CLIENT_ID, "exp": now + 300, "iat": now, **claims}
    payload = {name: value for name, value in payload.items() if value is not _OMIT}
    header = {"alg": alg, "kid": _KEY_FOR_ALG[alg].kid}
    return jws.serialize_compact(header, json.dumps(payload).encode(), key or _KEY_FOR_ALG[alg], algorithms=[alg])


_OMIT = object()
"""Sentinel letting a test drop a claim the helper otherwise always sets."""


async def _userinfo_app(scope: Any, receive: Any, send: Any) -> None:
    """A minimal ASGI userinfo endpoint, to prove a transport factory is honored."""
    del scope, receive
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": json.dumps({"sub": "u-1"}).encode()})


def metadata(*, waive: tuple[UrlField, ...] = (), **overrides: Any) -> ServerMetadata:
    """Build discovered metadata for the test issuer, with ``overrides`` applied.

    Args:
        waive: The URL fields the metadata accepts plain HTTP for. A test that passes a plain-HTTP
            URL states the waiver it needs, so a test that states none still meets the rule.
        **overrides: The field values to replace.

    Returns:
        The built metadata.
    """
    base: dict[str, Any] = {
        "authorize_url": AUTHORIZE_URL,
        "token_url": TOKEN_URL,
        "userinfo_url": USERINFO_URL,
        "jwks_url": JWKS_URL,
        "issuer": ISSUER,
    }
    base.update(overrides)
    if waive:
        return ServerMetadata.unsafe.allow_plain_http(*waive, **base)
    return ServerMetadata(**base)


class TestDiscoveryUrl:
    """Deriving the configuration document's URL from an issuer."""

    def test_appends_the_well_known_suffix_to_the_issuer_path(self):
        """The document lives under the issuer's own path (Discovery 1.0 section 4)."""
        assert discovery_url(ISSUER) == DOCUMENT_URL

    def test_preserves_a_realm_path_rather_than_resolving_against_the_root(self):
        """A root-absolute join would drop ``/realms/acme`` and probe the host root."""
        assert discovery_url("https://sso.example.com/realms/acme").startswith("https://sso.example.com/realms/acme/")

    def test_tolerates_a_trailing_slash_on_the_issuer(self):
        """A trailing slash does not produce a double slash before the suffix."""
        assert discovery_url(f"{ISSUER}/") == DOCUMENT_URL

    def test_handles_an_issuer_at_the_host_root(self):
        """An issuer with no path still gets the well-known suffix."""
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
    """Fetching and validating an OpenID provider's configuration document."""

    async def test_a_document_carrying_fields_this_library_does_not_model_still_discovers(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """Discovered metadata refuses a field it does not define, so the document must be read field by field."""
        httpx_mock.add_response(
            url=DOCUMENT_URL,
            json=document(
                response_types_supported=["code"],
                grant_types_supported=["authorization_code", "refresh_token"],
                subject_types_supported=["public"],
                id_token_signing_alg_values_supported=["RS256"],
                claims_supported=["sub", "email"],
                request_parameter_supported=False,
                service_documentation="https://as.example.com/docs",
            ),
        )

        discovered = await discover(ISSUER)

        assert discovered.issuer == ISSUER
        assert discovered.token_url == TOKEN_URL

    async def test_reads_every_endpoint_from_the_document(self, httpx_mock: HTTPXMock):
        """Each endpoint the flow needs is read from its documented field."""
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

        with pytest.raises(OidcDiscoveryError, match="declares a different issuer") as exc_info:
            await discover(ISSUER)
        assert exc_info.value.kind is FailureKind.REFUSED
        assert isinstance(exc_info.value.__cause__, IssuerNotDeclaredError)

    async def test_refuses_a_document_that_differs_only_by_a_trailing_slash(self, httpx_mock: HTTPXMock):
        """Two issuers differing by a slash are two different strings downstream."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(issuer=f"{ISSUER}/"))

        with pytest.raises(OidcDiscoveryError, match="declares a different issuer"):
            await discover(ISSUER)

    async def test_refuses_a_document_declaring_no_issuer(self, httpx_mock: HTTPXMock):
        """With no issuer there is nothing to match against, so the document is refused."""
        payload = document()
        del payload["issuer"]
        httpx_mock.add_response(url=DOCUMENT_URL, json=payload)

        with pytest.raises(OidcDiscoveryError, match="declares no issuer") as exc_info:
            await discover(ISSUER)
        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize("value", [None, ""])
    async def test_refuses_a_document_without_a_signing_key_set(self, httpx_mock: HTTPXMock, value: str | None) -> None:
        """OpenID Connect Discovery 1.0 section 3 makes ``jwks_uri`` REQUIRED."""
        payload = document(jwks_uri=value)
        if value is None:
            del payload["jwks_uri"]
        httpx_mock.add_response(url=DOCUMENT_URL, json=payload)

        with pytest.raises(OidcDiscoveryError, match="names no signing key set"):
            await discover(ISSUER)

    async def test_refuses_a_document_missing_an_endpoint(self, httpx_mock: HTTPXMock):
        """A document without the token endpoint cannot drive the code flow."""
        payload = document()
        del payload["token_endpoint"]
        httpx_mock.add_response(url=DOCUMENT_URL, json=payload)

        with pytest.raises(OidcDiscoveryError, match="missing an endpoint"):
            await discover(ISSUER)

    async def test_reports_a_non_200_document(self, httpx_mock: HTTPXMock):
        """A non-200 response is a discovery failure, reported with its status."""
        httpx_mock.add_response(url=DOCUMENT_URL, status_code=404)

        with pytest.raises(OidcDiscoveryError, match="HTTP 404"):
            await discover(ISSUER)

    async def test_a_redirect_raises_with_a_hint_and_logs_only_at_debug(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ):
        """Redirects are not followed, so a CDN-fronted provider fails.

        The exception carries the actionable hint, not the provider-controlled
        redirect target, and a path that raises does not log a WARNING.
        """
        target = "https://elsewhere.example/realms/acme/.well-known/openid-configuration"
        httpx_mock.add_response(url=DOCUMENT_URL, status_code=301, headers={"location": target})

        with (
            caplog.at_level(logging.DEBUG, logger="apron_auth.providers.oidc"),
            pytest.raises(OidcDiscoveryError, match="pass the canonical document URL as document_url") as excinfo,
        ):
            await discover(ISSUER)

        assert "HTTP 301" in str(excinfo.value)
        assert "elsewhere.example" not in str(excinfo.value)
        assert "elsewhere.example" not in caplog.text
        assert all(record.levelno == logging.DEBUG for record in caplog.records)

    async def test_reports_a_non_json_document(self, httpx_mock: HTTPXMock):
        """A body that does not parse as JSON is a discovery failure."""
        httpx_mock.add_response(url=DOCUMENT_URL, text="not json")

        with pytest.raises(OidcDiscoveryError, match="not JSON"):
            await discover(ISSUER)

    async def test_reports_a_deeply_nested_document(self, httpx_mock: HTTPXMock) -> None:
        """A body that nests too deeply to decode is a discovery failure, not a raw recursion error."""
        httpx_mock.add_response(url=DOCUMENT_URL, content=b"[" * 100_000 + b"]" * 100_000)

        with pytest.raises(OidcDiscoveryError, match="not JSON"):
            await discover(ISSUER)

    async def test_honors_a_document_url_override(self, httpx_mock: HTTPXMock):
        """An explicit document URL is fetched in place of the well-known one."""
        override = "https://sso.example.com/nonstandard-config"
        httpx_mock.add_response(url=override, json=document())

        discovered = await discover(ISSUER, document_url=override)

        assert discovered.issuer == ISSUER

    async def test_an_override_does_not_loosen_the_issuer_check(self, httpx_mock: HTTPXMock):
        """An overridden document must still name the configured issuer."""
        override = "https://sso.example.com/nonstandard-config"
        httpx_mock.add_response(url=override, json=document(issuer="https://attacker.example"))

        with pytest.raises(OidcDiscoveryError, match="declares a different issuer"):
            await discover(ISSUER, document_url=override)

    async def test_reports_a_malformed_issuer(self):
        """``urlparse`` rejects an unterminated IPv6 literal before any URL is built.

        The bare ``ValueError`` it raises would otherwise escape ``discover``,
        which documents ``OidcDiscoveryError`` for every bad input.
        """
        with pytest.raises(OidcDiscoveryError, match="issuer is malformed"):
            await discover("https://[::1")

    async def test_reports_a_malformed_document_url_override(self):
        """An unparseable override surfaces as the ``OidcDiscoveryError`` this module documents."""
        with pytest.raises(OidcDiscoveryError, match="document URL is malformed"):
            await discover(ISSUER, document_url="https://[::1")

    async def test_refuses_a_document_url_with_a_bad_port_as_configuration(self):
        """A port that cannot be read is a malformed URL, found before any fetch and charged to the caller."""
        with pytest.raises(OidcDiscoveryError, match="document URL is malformed") as exc_info:
            await discover(ISSUER, document_url="https://sso.example.com:port/config")
        assert exc_info.value.kind is FailureKind.CONFIGURATION

    async def test_refuses_an_endpoint_with_a_bad_port_as_the_providers_fault(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(token_endpoint="https://idp.example:port/token"))

        with pytest.raises(OidcDiscoveryError, match="token endpoint is malformed") as exc_info:
            await discover(ISSUER)
        assert exc_info.value.kind is FailureKind.REFUSED

    async def test_reports_an_unreachable_document(self, httpx_mock: HTTPXMock):
        """A transport error surfaces as ``OidcDiscoveryError``, not a raw httpx error."""
        httpx_mock.add_exception(httpx.ConnectError("no route"), url=DOCUMENT_URL)

        with pytest.raises(OidcDiscoveryError, match="could not fetch") as excinfo:
            await discover(ISSUER)

        assert "network error" in str(excinfo.value)
        assert "ConnectError" not in str(excinfo.value)

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


class TestDiscoveryTransportFactory:
    """The transport factory that lets a caller apply host policy to discovery."""

    @staticmethod
    def _factory(seen: list[str]):
        """A transport factory recording each URL and serving the document from memory."""

        def factory(url: str) -> httpx.AsyncBaseTransport:
            """Record the URL and serve the document from memory."""
            seen.append(url)
            return httpx.MockTransport(lambda request: httpx.Response(200, json=document()))

        return factory

    async def test_routes_the_document_fetch_through_the_factory(self):
        """``transport_factory`` is the documented host-policy hook for discovery."""
        seen: list[str] = []

        discovered = await discover(ISSUER, transport_factory=self._factory(seen))

        assert seen == [DOCUMENT_URL]
        assert discovered.issuer == ISSUER

    async def test_the_factory_sees_a_document_url_override(self):
        """An override relocates the fetch, and the factory is asked about the new URL."""
        seen: list[str] = []
        override = "https://sso.example.com/nonstandard-config"

        await discover(ISSUER, document_url=override, transport_factory=self._factory(seen))

        assert seen == [override]

    async def test_a_refusing_factory_surfaces_as_a_discovery_error(self) -> None:
        """A host-policy refusal is a discovery failure, not the factory's own exception."""

        def refuse(url: str) -> httpx.AsyncBaseTransport:
            raise PermissionError("blocked host secret-detail")

        with pytest.raises(OidcDiscoveryError, match="could not fetch") as excinfo:
            await discover(ISSUER, transport_factory=refuse)

        assert "secret-detail" not in str(excinfo.value)
        assert isinstance(excinfo.value.__cause__, PermissionError)


class TestHttpsRequirement:
    """Plain ``http`` is refused unless the caller opts in."""

    async def test_refuses_an_http_issuer(self):
        """The issuer anchors trust, so it must be authenticated by TLS."""
        with pytest.raises(OidcDiscoveryError, match="issuer must use https"):
            await discover("http://sso.example.com/realms/acme")

    def test_discovery_url_refuses_an_http_issuer(self):
        """``discovery_url`` applies the same https rule as ``discover``."""
        with pytest.raises(OidcDiscoveryError, match="issuer must use https"):
            discovery_url("http://sso.example.com/realms/acme")

    async def test_refuses_an_http_document_url_override(self):
        """An explicit document URL is held to the https rule too."""
        with pytest.raises(OidcDiscoveryError, match="document URL must use https") as exc_info:
            await discover(ISSUER, document_url="http://sso.example.com/config")
        assert exc_info.value.kind is FailureKind.CONFIGURATION

    @pytest.mark.parametrize(
        ("field", "label"),
        [
            ("authorization_endpoint", "authorization endpoint"),
            ("token_endpoint", "token endpoint"),
            ("userinfo_endpoint", "userinfo endpoint"),
            ("revocation_endpoint", "revocation endpoint"),
            ("registration_endpoint", "registration endpoint"),
            ("jwks_uri", "signing key set"),
        ],
    )
    async def test_refuses_an_http_endpoint(self, httpx_mock: HTTPXMock, field: str, label: str):
        """A document advertising a clear-text endpoint is refused by default."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(**{field: "http://idp.example/endpoint"}))

        with pytest.raises(OidcDiscoveryError, match=f"{label} must use https") as exc_info:
            await discover(ISSUER)
        assert exc_info.value.kind is FailureKind.REFUSED

    async def test_accepts_http_with_the_explicit_opt_in(self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture):
        """Local development can opt in, and the opt-in is audible in the logs."""
        issuer = "http://localhost:8080/realms/dev"
        httpx_mock.add_response(
            url=f"{issuer}/.well-known/openid-configuration",
            json=document(
                issuer=issuer,
                authorization_endpoint=f"{issuer}/auth",
                token_endpoint=f"{issuer}/token",
                userinfo_endpoint=f"{issuer}/userinfo",
            ),
        )

        with caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"):
            discovered = await discover(issuer, allow_insecure_http=True)

        assert discovered.token_url == f"{issuer}/token"
        assert "token endpoint is plain http" in caplog.text
        assert "issuer is plain http" in caplog.text

    async def test_https_does_not_warn(self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture):
        """An https issuer logs nothing, even with the opt-in set."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=document())

        with caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"):
            await discover(ISSUER, allow_insecure_http=True)

        assert caplog.text == ""

    @pytest.mark.parametrize(
        "field",
        ["issuer", "authorize_url", "token_url", "revocation_url", "registration_url", "userinfo_url"],
    )
    def test_metadata_built_without_discovery_states_its_own_waiver(self, field: str) -> None:
        """Metadata that never passed through ``discover`` is held to the rule where it is built."""
        base: dict[str, Any] = {"authorize_url": AUTHORIZE_URL, "token_url": TOKEN_URL, "issuer": ISSUER}
        base[field] = "http://idp.example/endpoint"

        with pytest.raises(ConfigurationError, match=f"{field} must use https"):
            ServerMetadata(**base)

    @pytest.mark.parametrize(
        ("field", "value", "label"),
        [
            ("issuer", "https://issuer.example.com/?q=1", "issuer"),
            ("jwks_url", "https://issuer.example.com/jwks#fragment", "signing key set"),
        ],
        ids=["issuer with a query", "key set with a fragment"],
    )
    def test_preset_states_the_url_rules_the_models_do_not(self, field: str, value: str, label: str) -> None:
        """A model states what a scheme must say. The shape of the URL is stated here."""
        with pytest.raises(ConfigurationError, match=label):
            preset(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scopes=[],
                metadata=metadata(**{field: value}),
            )

    def test_preset_waives_nothing_without_the_opt_in(self) -> None:
        """A waiver follows the caller's opt-in, never the fact that a URL happens to be plain http."""
        with pytest.raises(ConfigurationError, match="redirect_uri must use https"):
            preset(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scopes=[],
                metadata=metadata(),
                redirect_uri="http://app.example.com/callback",
            )

    def test_preset_carries_a_waiver_from_the_metadata_into_the_config(self) -> None:
        """The config sends the client's secret to the token endpoint, so it records the waiver too."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(token_url="http://idp.example/token", waive=(UrlField.TOKEN_URL,)),
            allow_insecure_http=True,
        )

        assert config.token_url == "http://idp.example/token"
        assert config.allow_insecure_http_for == frozenset({UrlField.TOKEN_URL})

    def test_preset_waives_a_plain_http_redirect_uri_with_the_opt_in(self) -> None:
        """The redirect URI is the config's own field, so the opt-in has to reach it."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(),
            redirect_uri="http://app.example.com/callback",
            allow_insecure_http=True,
        )

        assert config.redirect_uri == "http://app.example.com/callback"
        assert config.allow_insecure_http_for == frozenset({UrlField.REDIRECT_URI})

    async def test_discover_waives_a_plain_http_issuer_off_loopback(self, httpx_mock: HTTPXMock) -> None:
        """A loopback issuer needs no waiver, so only one off loopback holds the opt-in to its field."""
        issuer = "http://idp.example/realms/dev"
        httpx_mock.add_response(
            url=f"{issuer}/.well-known/openid-configuration",
            json=document(
                issuer=issuer,
                authorization_endpoint=f"{issuer}/auth",
                token_endpoint=f"{issuer}/token",
                userinfo_endpoint=f"{issuer}/userinfo",
                jwks_uri=f"{issuer}/certs",
            ),
        )

        discovered = await discover(issuer, allow_insecure_http=True)

        assert discovered.issuer == issuer
        assert discovered.allow_insecure_http_for == frozenset(
            {UrlField.AUTHORIZE_URL, UrlField.ISSUER, UrlField.JWKS_URL, UrlField.TOKEN_URL, UrlField.USERINFO_URL}
        )

    def test_identity_handler_refuses_an_http_userinfo_endpoint(self) -> None:
        """A waiver on the metadata is not a waiver on the handler, which states its own."""
        with pytest.raises(ConfigurationError, match="userinfo endpoint must use https"):
            identity_handler(metadata(userinfo_url="http://idp.example/userinfo", waive=(UrlField.USERINFO_URL,)))

    def test_identity_handler_accepts_http_userinfo_with_the_explicit_opt_in(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The opt-in on ``identity_handler`` matches the one on ``discover`` and ``preset``."""
        with caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"):
            identity_handler(metadata(userinfo_url="http://localhost:8080/userinfo"), allow_insecure_http=True)

        assert "userinfo endpoint is plain http" in caplog.text

    def test_handler_constructor_refuses_an_http_userinfo_endpoint(self) -> None:
        """Building the handler directly applies the same scheme rule as the factory."""
        with pytest.raises(ConfigurationError, match="userinfo endpoint must use https"):
            OidcIdentityHandler(issuer=ISSUER, jwks_url=JWKS_URL, userinfo_url="http://idp.example/userinfo")

    def test_handler_constructor_accepts_http_userinfo_with_the_explicit_opt_in(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The opt-in on the constructor matches the one on the factory."""
        with caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"):
            OidcIdentityHandler(
                issuer=ISSUER,
                jwks_url=JWKS_URL,
                userinfo_url="http://localhost:8080/userinfo",
                allow_insecure_http=True,
            )

        assert "userinfo endpoint is plain http" in caplog.text


class TestUrlValidation:
    """Issuer and endpoint URLs are validated as absolute, well-formed URLs."""

    @pytest.mark.parametrize("field", ["authorization_endpoint", "token_endpoint"])
    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "/relative/path",
            "javascript:alert(1)",
            "idp.example/token",
            f"{ISSUER}/token#frag",
            f"{ISSUER}/token#",
            5,
        ],
    )
    async def test_refuses_a_bad_required_endpoint(self, httpx_mock: HTTPXMock, field: str, bad: object):
        """An empty, relative, scripting or fragment-bearing endpoint never becomes a config."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(**{field: bad}))

        with pytest.raises(OidcDiscoveryError, match="endpoint"):
            await discover(ISSUER)

    @pytest.mark.parametrize("field", ["userinfo_endpoint", "revocation_endpoint", "registration_endpoint"])
    @pytest.mark.parametrize("bad", ["/relative", "javascript:alert(1)", f"{ISSUER}/x#frag"])
    async def test_refuses_a_bad_optional_endpoint_when_present(self, httpx_mock: HTTPXMock, field: str, bad: str):
        """An optional endpoint is validated whenever the document names one."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(**{field: bad}))

        with pytest.raises(OidcDiscoveryError, match="endpoint"):
            await discover(ISSUER)

    @pytest.mark.parametrize(
        ("field", "attribute"),
        [
            ("userinfo_endpoint", "userinfo_url"),
            ("revocation_endpoint", "revocation_url"),
            ("registration_endpoint", "registration_url"),
        ],
    )
    async def test_treats_an_empty_optional_endpoint_as_absent(
        self, httpx_mock: HTTPXMock, field: str, attribute: str
    ) -> None:
        """An empty string names no endpoint, so discovery carries on without it."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(**{field: ""}))

        discovered = await discover(ISSUER)

        assert getattr(discovered, attribute) is None

    async def test_names_the_offending_field(self, httpx_mock: HTTPXMock):
        """The error says which member was wrong, so an operator can find it."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(token_endpoint="javascript:alert(1)"))

        with pytest.raises(OidcDiscoveryError, match="token endpoint"):
            await discover(ISSUER)

    @pytest.mark.parametrize(
        ("issuer", "match"),
        [
            ("https://sso.example.com/realms/acme?x=1", "query"),
            ("https://sso.example.com/realms/acme?", "query"),
            ("https://sso.example.com/realms/acme#frag", "fragment"),
            ("https://sso.example.com/realms/acme#", "fragment"),
            ("https://user@sso.example.com/realms/acme", "userinfo"),
            ("https://user:pw@sso.example.com/realms/acme", "userinfo"),  # pragma: allowlist secret
        ],
    )
    async def test_refuses_an_issuer_with_a_query_fragment_or_userinfo(self, issuer: str, match: str):
        """Discovery 1.0 section 4.1 forbids each, and the issuer ends up in ``provider``."""
        with pytest.raises(OidcDiscoveryError, match=match):
            await discover(issuer)

    async def test_accepts_a_port_and_path_in_the_issuer(self, httpx_mock: HTTPXMock):
        """A port is not userinfo, so ordinary self-hosted issuers still work."""
        issuer = "https://sso.example.com:8443/realms/acme"
        httpx_mock.add_response(
            url=f"{issuer}/.well-known/openid-configuration",
            json=document(issuer=issuer),
        )

        assert (await discover(issuer)).issuer == issuer


class TestSecurityRelevantLists:
    """Lists that gate a security refusal must be well-formed when present."""

    @pytest.mark.parametrize("field", ["code_challenge_methods_supported", "token_endpoint_auth_methods_supported"])
    @pytest.mark.parametrize("bad", ["plain", 5, {"S256": True}, ["S256", 1]])
    async def test_refuses_a_malformed_list(self, httpx_mock: HTTPXMock, field: str, bad: object):
        """A string would otherwise read as "not advertised" and take the permissive branch."""
        httpx_mock.add_response(url=DOCUMENT_URL, json=document(**{field: bad}))

        with pytest.raises(OidcDiscoveryError, match=field):
            await discover(ISSUER)

    async def test_an_absent_list_is_not_an_error(self, httpx_mock: HTTPXMock):
        """Entra omits the PKCE field, and that stays legal."""
        body = document()
        del body["code_challenge_methods_supported"]
        httpx_mock.add_response(url=DOCUMENT_URL, json=body)

        assert (await discover(ISSUER)).code_challenge_methods == []


class TestPreset:
    """Building a provider config from discovered metadata."""

    def test_builds_a_config_from_discovered_metadata(self):
        """The config takes its endpoints and issuer from the metadata."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=["email", "profile"],
            metadata=metadata(),
        )

        assert config.authorize_url == AUTHORIZE_URL
        assert config.token_url == TOKEN_URL
        assert config.issuer == ISSUER
        assert config.revocation_url is None

    def test_merges_the_openid_scope(self):
        """Without it the provider runs a plain OAuth flow and returns no ID token."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=["email"],
            metadata=metadata(),
        )

        assert "openid" in config.scopes

    def test_declares_a_revocation_endpoint_when_the_provider_advertises_one(self):
        """The config names no provider, so the client revokes through RFC 7009 revocation."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(revocation_url=f"{ISSUER}/protocol/openid-connect/revoke"),
        )

        assert config.revocation_url == f"{ISSUER}/protocol/openid-connect/revoke"

    def test_carries_iss_support_onto_the_config(self):
        """Advertised RFC 9207 ``iss`` support makes the callback ``iss`` required."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(iss_parameter_supported=True),
        )

        assert config.require_iss is True

    def test_enables_pkce_when_the_provider_advertises_s256(self):
        """PKCE is on when ``S256`` is advertised."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(code_challenge_methods=["S256"]),
        )

        assert config.use_pkce is True

    def test_warns_when_the_provider_advertises_no_pkce_support(self, caplog: pytest.LogCaptureFixture):
        """PKCE binds the code only if the provider enforces it, so silence would overclaim."""
        with caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"):
            preset(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scopes=[],
                metadata=metadata(code_challenge_methods=[]),
            )

        assert "does not advertise PKCE" in caplog.text

    def test_does_not_warn_when_s256_is_advertised(self, caplog: pytest.LogCaptureFixture):
        """An explicit S256 advertisement is the quiet path."""
        with caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"):
            preset(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scopes=[],
                metadata=metadata(code_challenge_methods=["S256"]),
            )

        assert caplog.text == ""

    def test_enables_pkce_when_the_provider_advertises_nothing(self):
        """A provider that does not implement PKCE ignores the extra parameters."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
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
                client_secret=CLIENT_SECRET,
                scopes=[],
                metadata=metadata(code_challenge_methods=methods),
            )

    def test_keeps_pkce_when_s256_appears_alongside_others(self):
        """Other advertised methods do not matter while ``S256`` is among them."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(code_challenge_methods=["plain", "S256"]),
        )

        assert config.use_pkce is True

    def test_prefers_client_secret_post_among_advertised_methods(self):
        """``client_secret_post`` wins when both secret methods are advertised."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(token_endpoint_auth_methods=["client_secret_basic", "client_secret_post"]),
        )

        assert config.token_endpoint_auth_method == TokenEndpointAuthMethod.CLIENT_SECRET_POST

    @pytest.mark.parametrize("secret", ["", "   "])
    def test_refuses_an_empty_client_secret(self, secret: str) -> None:
        """A confidential client with no secret would only fail later, at the token endpoint."""
        with pytest.raises(ConfigurationError, match="client secret"):
            preset(client_id=CLIENT_ID, client_secret=secret, scopes=[], metadata=metadata())

    def test_uses_basic_when_the_provider_advertises_no_method(self) -> None:
        """An absent list means ``client_secret_basic`` (OpenID Connect Discovery 1.0 section 3)."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(token_endpoint_auth_methods=[]),
        )

        assert config.token_endpoint_auth_method == TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

    def test_falls_back_to_basic_when_that_is_all_that_is_advertised(self):
        """``client_secret_basic`` is used when it is the only method on offer."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(token_endpoint_auth_methods=["client_secret_basic"]),
        )

        assert config.token_endpoint_auth_method == TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

    def test_refuses_a_provider_offering_only_unperformable_methods(self):
        """Only unsupported auth methods is a configuration error, not a silent fallback."""
        with pytest.raises(ConfigurationError, match="no token-endpoint auth method"):
            preset(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scopes=[],
                metadata=metadata(token_endpoint_auth_methods=["private_key_jwt"]),
            )

    def test_refuses_metadata_naming_no_signing_key_set(self) -> None:
        """A config whose ID tokens could not be verified is not built."""
        with pytest.raises(ConfigurationError, match="names no signing key set"):
            preset(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, scopes=[], metadata=metadata(jwks_url=None))

    def test_refuses_metadata_naming_no_issuer(self):
        """An issuer-less config would silently skip every ``iss`` check.

        ``identity_handler`` refuses the same input; the two factories must
        agree, because a config that never validates ``iss`` has no trust
        anchor at all.
        """
        with pytest.raises(ConfigurationError, match="names no issuer"):
            preset(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scopes=[],
                metadata=metadata(issuer=None),
            )

    def test_takes_keyword_arguments_only(self):
        """Locking the signature now keeps a later optional ``client_secret`` non-breaking."""
        with pytest.raises(TypeError):
            preset(CLIENT_ID, CLIENT_SECRET, [], metadata())  # type: ignore[misc]

    def test_asserts_no_domain_ownership(self):
        """OpenID Connect standardizes no domain-ownership claim."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(),
        )

        assert config.can_assert_domain_ownership is False

    def test_adds_no_extra_params_of_its_own(self):
        """No product-specific authorization parameters are added to a generic provider."""
        config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(),
        )

        assert config.extra_params == {}


class TestIdentityHandlerFactory:
    """Building the identity handler from discovered metadata."""

    def test_builds_a_handler_from_metadata(self):
        """Metadata naming an issuer yields an ``OidcIdentityHandler``."""
        assert isinstance(identity_handler(metadata()), OidcIdentityHandler)

    def test_builds_a_handler_without_a_userinfo_endpoint(self):
        """Identity can rest on the ID token alone."""
        assert isinstance(identity_handler(metadata(userinfo_url=None)), OidcIdentityHandler)

    def test_refuses_metadata_naming_no_issuer(self) -> None:
        """A handler with no issuer could not check that a config belongs to it."""
        with pytest.raises(ConfigurationError, match="names no issuer"):
            identity_handler(metadata(issuer=None))

    def test_refuses_metadata_without_a_signing_key_set(self) -> None:
        """A handler that cannot verify ID tokens is not built."""
        with pytest.raises(ConfigurationError, match="names no signing key set"):
            identity_handler(metadata(jwks_url=None))

    def test_refuses_an_insecure_signing_key_set_url(self) -> None:
        """The key set URL meets the same rule as every other endpoint."""
        with pytest.raises(ConfigurationError, match="signing key set must use https"):
            identity_handler(metadata(jwks_url="http://sso.example.com/certs", waive=(UrlField.JWKS_URL,)))


class TestHandlerInference:
    """Test that a generic config never resolves to another provider's identity handler."""

    @pytest.fixture(
        params=[
            pytest.param(
                (
                    "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
                    "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize",
                    "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token",
                ),
                id="microsoft",
            ),
            pytest.param(
                (
                    "https://accounts.google.com",
                    "https://accounts.google.com/o/oauth2/v2/auth",
                    "https://oauth2.googleapis.com/token",
                ),
                id="google",
            ),
        ]
    )
    def claimed_metadata(self, request: pytest.FixtureRequest) -> ServerMetadata:
        """Return metadata for an issuer on a host that a built-in provider also serves."""
        issuer, authorize_url, token_url = request.param
        return metadata(issuer=issuer, authorize_url=authorize_url, token_url=token_url)

    def test_a_generic_config_on_a_claimed_host_names_no_provider(self, claimed_metadata: ServerMetadata) -> None:
        """A built-in handler would change ``provider`` and so every user's ``identity_key()``."""
        config = preset(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, scopes=[], metadata=claimed_metadata)

        assert config.provider is None

    async def test_a_client_without_a_handler_refuses_before_any_request(
        self, claimed_metadata: ServerMetadata, httpx_mock: HTTPXMock
    ) -> None:
        """The client raises the unsupported-identity error and sends nothing to the provider."""
        config = preset(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, scopes=[], metadata=claimed_metadata)
        client = OAuthClient(config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(FreshTokenSet(access_token="access"))

        assert httpx_mock.get_requests() == []

    async def test_a_client_with_the_generic_handler_establishes_identity(
        self, claimed_metadata: ServerMetadata, httpx_mock: HTTPXMock
    ) -> None:
        """The explicit handler is the one source of identity for a config that names no provider."""
        config = preset(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, scopes=[], metadata=claimed_metadata)
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})
        client = OAuthClient(config, identity_handler=identity_handler(claimed_metadata))

        identity = await client.fetch_identity(FreshTokenSet(access_token="access"))

        assert identity.identity_key() == (f"oidc:{claimed_metadata.issuer}", "u-1")


class TestOidcIdentity:
    """Establishing identity from an ID token and the userinfo endpoint."""

    @pytest.fixture(autouse=True)
    def _published_keys(self, httpx_mock: HTTPXMock) -> None:
        """Serve the issuer's key set to any test that sends an ID token."""
        httpx_mock.add_response(url=JWKS_URL, json=PUBLISHED_KEYS, is_optional=True, is_reusable=True)

    @pytest.fixture
    def handler(self) -> OidcIdentityHandler:
        """An identity handler for the test issuer and client."""
        return identity_handler(metadata())

    @pytest.fixture
    def trusting_handler(self) -> OidcIdentityHandler:
        """A handler whose operator trusts the issuer's ``email_verified`` claim."""
        return identity_handler(metadata(), trust_email_verified=True)

    @pytest.fixture
    def config(self) -> ProviderConfig:
        """The provider config the handler's tokens were issued under."""
        built = preset(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, scopes=[], metadata=metadata())
        return built

    async def test_reads_identity_from_userinfo_and_the_id_token(
        self, trusting_handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """Fields come from both documents, and ``raw`` keeps them apart."""
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

        identity = await trusting_handler.fetch_identity(
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

    async def test_reports_email_verified_as_unasserted_by_default(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """A self-run issuer's ``email_verified`` is not honored unless the operator opts in."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})

        identity = await handler.fetch_identity(
            IdentityMaterial(
                access_token="access",
                id_token=id_token(sub="u-1", email="ceo@other-tenant.com", email_verified=True),
            ),
            config,
        )

        assert identity.email == "ceo@other-tenant.com"
        assert identity.email_verified is None
        assert identity.verified_email() is None

    async def test_reports_email_verified_when_the_operator_trusts_the_issuer(
        self, trusting_handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """``trust_email_verified`` restores the issuer's claim on the profile."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})

        identity = await trusting_handler.fetch_identity(
            IdentityMaterial(
                access_token="access",
                id_token=id_token(sub="u-1", email="person@acme.com", email_verified=True),
            ),
            config,
        )

        assert identity.email_verified is True
        assert identity.verified_email() == "person@acme.com"

    async def test_default_still_keeps_identity_key_and_raw_claims(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """Dropping the flag from the profile does not hide it from ``raw``."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})

        identity = await handler.fetch_identity(
            IdentityMaterial(
                access_token="access",
                id_token=id_token(sub="u-1", email="person@acme.com", email_verified=True),
            ),
            config,
        )

        assert identity.identity_key() == (f"oidc:{ISSUER}", "u-1")
        assert identity.raw["id_token"]["email_verified"] is True

    async def test_works_without_an_id_token(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """Userinfo alone identifies the user, but cannot vouch for email verification."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1", "email": "person@acme.com"})

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

        assert identity.subject == "u-1"
        assert identity.email_verified is None

    async def test_works_without_a_userinfo_endpoint(self, config: ProviderConfig):
        """A provider advertising none still identifies someone via the ID token."""
        handler = identity_handler(metadata(userinfo_url=None))

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
        self, trusting_handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """The trust-bearing document wins on the claim an access decision rests on."""
        httpx_mock.add_response(
            url=USERINFO_URL, json={"sub": "u-1", "email": "person@acme.com", "email_verified": True}
        )

        identity = await trusting_handler.fetch_identity(
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
        """An ``iss`` other than the configured issuer is refused."""
        with pytest.raises(TokenValidationError, match=r"invalid iss claim") as exc_info:
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(iss="https://attacker.example")),
                config,
            )
        assert exc_info.value.reason is TokenValidationReason.UNKNOWN_ISSUER

    @pytest.mark.parametrize("iss", [[ISSUER], ["https://attacker.example", ISSUER]])
    async def test_refuses_an_id_token_naming_its_issuer_in_a_list(
        self, handler: OidcIdentityHandler, config: ProviderConfig, iss: list[str]
    ) -> None:
        """``iss`` must be exactly the issuer string, not a list that contains it."""
        with pytest.raises(IdentityFetchError, match=r"invalid iss claim"):
            await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=id_token(iss=iss)), config)

    async def test_refuses_an_id_token_minted_for_another_client(
        self, handler: OidcIdentityHandler, config: ProviderConfig
    ):
        """An ``aud`` that does not name this client is refused."""
        with pytest.raises(TokenValidationError, match=r"invalid aud claim") as exc_info:
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(aud="someone-else")),
                config,
            )
        assert exc_info.value.reason is TokenValidationReason.AUDIENCE

    async def test_accepts_an_audience_array_naming_this_client(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """A multi-audience token is accepted when it names this client and ``azp`` matches."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})

        identity = await handler.fetch_identity(
            IdentityMaterial(
                access_token="access", id_token=id_token(sub="u-1", aud=["other", CLIENT_ID], azp=CLIENT_ID)
            ),
            config,
        )

        assert identity.subject == "u-1"

    async def test_refuses_an_expired_id_token(self, handler: OidcIdentityHandler, config: ProviderConfig):
        """A token expired well beyond the leeway is refused as expired."""
        with pytest.raises(TokenExpiredError, match=r"has expired") as exc_info:
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(exp=time.time() - 3600)),
                config,
            )
        assert exc_info.value.reason is TokenValidationReason.EXPIRED

    async def test_tolerates_clock_skew_within_the_leeway(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """A token expired by less than the leeway is still accepted."""
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
        with pytest.raises(IdentityFetchError, match=rf"missing the {claim} claim"):
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

    async def test_refuses_a_userinfo_response_naming_no_subject_beside_an_id_token(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """Section 5.3.2 requires an exact match, and an absent ``sub`` is not one.

        Otherwise the ID token's subject would pick up a verified email from a
        document never bound to it.
        """
        httpx_mock.add_response(url=USERINFO_URL, json={"email": "person@acme.com", "email_verified": True})

        with pytest.raises(IdentityFetchError, match="names no subject"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1")),
                config,
            )

    @pytest.mark.parametrize(
        ("token", "message"),
        [
            ("not-a-jwt", "not a compact signed token"),
            (
                f"{_b64(b'{}')}.{_b64(json.dumps({'sub': 'u-1'}).encode())}.sig",
                "not a compact signed token",
            ),
            (f"{_b64(json.dumps({'alg': 'RS256'}).encode())}.{_b64(b'[1]')}.sig", "signature did not verify"),
        ],
    )
    async def test_refuses_an_id_token_that_does_not_verify_before_userinfo(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock, token: str, message: str
    ) -> None:
        """A token that does not verify stops the sign-in, so identity never rests on userinfo alone."""
        with pytest.raises(IdentityFetchError, match=message) as excinfo:
            await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=token), config)

        assert token not in str(excinfo.value)
        assert USERINFO_URL not in [str(request.url) for request in httpx_mock.get_requests()]

    async def test_refuses_an_id_token_signed_by_another_key(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ) -> None:
        """A forged token with valid claims is refused, even when userinfo would succeed."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"}, is_optional=True)
        forged = id_token(key=jwk.RSAKey.generate_key(2048))

        with pytest.raises(IdentityFetchError, match="signature did not verify"):
            await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=forged), config)

    async def test_verifies_before_any_userinfo_request(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ) -> None:
        """A forged token stops the sign-in before the access token is sent anywhere."""
        forged = id_token(key=jwk.RSAKey.generate_key(2048))

        with pytest.raises(IdentityFetchError):
            await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=forged), config)

        assert [str(request.url) for request in httpx_mock.get_requests()] == [JWKS_URL]

    async def test_fetches_the_key_set_through_the_transport_factory(self, config: ProviderConfig) -> None:
        """Host policy covers the key set fetch, not only userinfo."""
        requested: list[str] = []

        def respond(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=PUBLISHED_KEYS if str(request.url) == JWKS_URL else {"sub": "u-1"})

        def factory(url: str) -> httpx.AsyncBaseTransport:
            requested.append(url)
            return httpx.MockTransport(respond)

        handler = identity_handler(metadata(), transport_factory=factory)

        await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=id_token()), config)

        assert JWKS_URL in requested

    async def test_refuses_when_neither_document_yields_a_subject(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """With no ``sub`` anywhere there is no one to identify."""
        httpx_mock.add_response(url=USERINFO_URL, json={"email": "person@acme.com"})

        with pytest.raises(IdentityFetchError, match="no subject"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    async def test_reports_a_failed_userinfo_request(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """An HTTP error from userinfo surfaces as ``IdentityFetchError``."""
        httpx_mock.add_response(url=USERINFO_URL, status_code=401)

        with pytest.raises(IdentityFetchError, match="Failed to fetch"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    @pytest.mark.parametrize("status", [401, 403, 500, 503])
    async def test_userinfo_failure_degrades_to_the_id_token(
        self,
        handler: OidcIdentityHandler,
        config: ProviderConfig,
        httpx_mock: HTTPXMock,
        caplog: pytest.LogCaptureFixture,
        status: int,
    ):
        """Entra and Keycloak refuse userinfo for a resource-API audience; the ID token still vouches."""
        httpx_mock.add_response(url=USERINFO_URL, status_code=status)

        with caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"):
            identity = await handler.fetch_identity(
                IdentityMaterial(
                    access_token="access",
                    id_token=id_token(sub="u-1", email="person@acme.com", name="A Person"),
                ),
                config,
            )

        assert identity.subject == "u-1"
        assert identity.email == "person@acme.com"
        assert identity.name == "A Person"
        assert identity.raw["userinfo"] == {}
        assert [record.getMessage() for record in caplog.records if record.name == "apron_auth.providers.oidc"] == [
            "OpenID userinfo request failed, identity rests on the ID token alone"
        ]

    async def test_a_scope_refusal_degrades_to_the_id_token_with_its_own_warning(
        self,
        handler: OidcIdentityHandler,
        config: ProviderConfig,
        httpx_mock: HTTPXMock,
        caplog: pytest.LogCaptureFixture,
    ):
        """A scope refusal is a configuration fault, so its warning differs from a failed request's."""
        httpx_mock.add_response(
            url=USERINFO_URL,
            status_code=403,
            headers={"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="openid profile"'},
        )

        with caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"):
            identity = await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1")), config
            )

        assert identity.subject == "u-1"
        assert [record.getMessage() for record in caplog.records if record.name == "apron_auth.providers.oidc"] == [
            "OpenID userinfo refused the token for lack of scope, identity rests on the ID token alone"
        ]

    async def test_userinfo_failure_without_an_id_token_still_raises(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """With no ID token, userinfo is the only source of a subject."""
        httpx_mock.add_response(url=USERINFO_URL, status_code=403)

        with pytest.raises(IdentityFetchError, match="Failed to fetch"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    async def test_maps_insufficient_scope_to_a_scope_error_without_an_id_token(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """RFC 6750 ``insufficient_scope`` means retrying the same token cannot succeed."""
        httpx_mock.add_response(
            url=USERINFO_URL,
            status_code=403,
            headers={"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="openid profile"'},
        )

        with pytest.raises(IdentityScopeNotGrantedError) as excinfo:
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    async def test_a_bare_403_is_not_a_scope_error(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """Only the RFC 6750 error code selects the scope error."""
        httpx_mock.add_response(url=USERINFO_URL, status_code=403, headers={"WWW-Authenticate": 'Bearer realm="x"'})

        with pytest.raises(IdentityFetchError) as excinfo:
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

        assert not isinstance(excinfo.value, IdentityScopeNotGrantedError)

    async def test_reads_a_scope_refusal_from_separate_header_lines(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ) -> None:
        """A server may send each challenge on its own ``WWW-Authenticate`` line."""
        httpx_mock.add_response(
            url=USERINFO_URL,
            status_code=403,
            headers=[
                ("WWW-Authenticate", 'Basic realm="x"'),
                ("WWW-Authenticate", 'Bearer error="insufficient_scope"'),
            ],
        )

        with pytest.raises(IdentityScopeNotGrantedError):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    @pytest.mark.parametrize("code", NEAR_MISS_SCOPE_CODES)
    async def test_a_near_miss_error_code_is_not_a_scope_error(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock, code: str
    ) -> None:
        """A near miss maps to the retryable fetch error, not to the scope error."""
        httpx_mock.add_response(
            url=USERINFO_URL, status_code=403, headers={"WWW-Authenticate": f'Bearer error="{code}"'}
        )

        with pytest.raises(IdentityFetchError) as excinfo:
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

        assert not isinstance(excinfo.value, IdentityScopeNotGrantedError)

    async def test_a_disagreeing_subject_still_raises_when_userinfo_succeeds(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """Degrading on failure does not weaken the section 5.3.2 check on success."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "someone-else"})

        with pytest.raises(IdentityFetchError, match="different subject"):
            await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=id_token(sub="u-1")), config)

    def test_refuses_a_userinfo_url_that_cannot_be_requested(self):
        """A URL the request itself would reject is the caller's own, so no handler is built on it."""
        userinfo = "operator-7f3a9c"

        with pytest.raises(ConfigurationError, match="userinfo endpoint is malformed") as excinfo:
            OidcIdentityHandler(issuer=ISSUER, jwks_url=JWKS_URL, userinfo_url=f"https://{userinfo}@idp.example/\x00")

        assert excinfo.value.kind is FailureKind.CONFIGURATION
        assert userinfo not in "".join(traceback.format_exception(excinfo.value))

    async def test_reports_a_token_that_cannot_be_sent(self, handler: OidcIdentityHandler, config: ProviderConfig):
        """A token that is not ASCII cannot go in a header, and the error must not repeat it."""
        token = "access-SECRET-\u00e9"

        with pytest.raises(IdentityFetchError, match="request failed") as excinfo:
            await handler.fetch_identity(IdentityMaterial(access_token=token), config)

        assert token not in repr(excinfo.value.args)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    async def test_reports_a_deeply_nested_userinfo_response(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """A body nested deeper than the decoder allows is a parse failure, not a raw recursion error."""
        httpx_mock.add_response(url=USERINFO_URL, content=b"[" * 100_000 + b"]" * 100_000)

        with pytest.raises(IdentityFetchError, match="Failed to parse") as excinfo:
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    async def test_reports_a_non_object_userinfo_response(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """Userinfo JSON that is not an object is refused."""
        httpx_mock.add_response(url=USERINFO_URL, json=["not", "an", "object"])

        with pytest.raises(IdentityFetchError, match="not a JSON object"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    async def test_refuses_a_multi_audience_token_without_azp(
        self, handler: OidcIdentityHandler, config: ProviderConfig
    ):
        """Section 3.1.3.7 step 4 — ``aud`` arrays are accepted, so the condition is reachable."""
        with pytest.raises(IdentityFetchError, match=r"missing the azp claim"):
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
        with pytest.raises(IdentityFetchError, match=r"invalid azp claim"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", azp="someone-else")),
                config,
            )

    async def test_accepts_a_single_audience_token_carrying_a_matching_azp(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """An ``azp`` naming this client is accepted on a single-audience token."""
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
        with pytest.raises(IdentityFetchError, match=r"invalid at_hash claim"):
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
        """``email_verified`` without an ``email`` in the same document is discarded."""
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
        with pytest.raises(IdentityFetchError, match=r"missing the sub claim"):
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
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"}, is_reusable=True)
        other_issuer = "https://sso.other.example"
        other_metadata = metadata(issuer=other_issuer, userinfo_url=None)
        other_config = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=other_metadata,
        )

        mine = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token=id_token(sub="u-1")), config
        )
        theirs = await identity_handler(other_metadata).fetch_identity(
            IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", iss=other_issuer)),
            other_config,
        )

        assert mine.identity_key() != theirs.identity_key()

    async def test_routes_the_userinfo_request_through_a_transport_factory(self, config: ProviderConfig):
        """The factory ``discover`` accepts must also cover the one other outbound call."""
        seen: list[str] = []

        def factory(url: str) -> httpx.AsyncBaseTransport:
            """Record the requested URL and serve it from the in-process userinfo app."""
            seen.append(url)
            return httpx.ASGITransport(app=_userinfo_app)

        handler = identity_handler(metadata(), transport_factory=factory)

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

        assert seen == [USERINFO_URL]
        assert identity.subject == "u-1"

    async def test_a_refusing_transport_factory_degrades_to_the_id_token(
        self, config: ProviderConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A host-policy refusal from the caller's factory is a failed userinfo call like any other."""

        def refuse_userinfo(url: str) -> httpx.AsyncBaseTransport:
            if url == USERINFO_URL:
                raise PermissionError("blocked host secret-detail")
            return httpx.MockTransport(lambda request: httpx.Response(200, json=PUBLISHED_KEYS))

        handler = identity_handler(metadata(), transport_factory=refuse_userinfo)

        with caplog.at_level(logging.WARNING, logger="apron_auth.providers.oidc"):
            identity = await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1")), config
            )

        assert identity.subject == "u-1"
        assert "userinfo request failed" in caplog.text
        assert "secret-detail" not in caplog.text

    async def test_a_refusing_transport_factory_without_an_id_token_raises(self, config: ProviderConfig) -> None:
        """With no ID token, the refusal surfaces as the handler's own error, not the factory's."""

        def refuse(url: str) -> httpx.AsyncBaseTransport:
            raise PermissionError("blocked host secret-detail")

        handler = identity_handler(metadata(), transport_factory=refuse)

        with pytest.raises(IdentityFetchError, match="Failed to fetch") as excinfo:
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

        assert "secret-detail" not in str(excinfo.value)
        assert isinstance(excinfo.value.__cause__, PermissionError)

    async def test_refuses_a_signed_userinfo_response(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ) -> None:
        """A signed userinfo response is named as unsupported, not reported as a broken body."""
        httpx_mock.add_response(
            url=USERINFO_URL,
            headers={"Content-Type": "application/jwt; charset=utf-8"},
            content=id_token(sub="u-1").encode(),
        )

        with pytest.raises(IdentityFetchError, match="signed userinfo"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    async def test_reports_an_unparseable_userinfo_body(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """HTTP 200 with a body that is not JSON at all — distinct from wrong-shaped JSON."""
        httpx_mock.add_response(url=USERINFO_URL, status_code=200, content=b"<html>nope</html>")

        with pytest.raises(IdentityFetchError, match="Failed to parse"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    @pytest.mark.parametrize("payload", [b"", b"{not json", b'["a","list"]'])
    async def test_refuses_a_signed_token_whose_payload_is_not_a_claims_object(
        self, handler: OidcIdentityHandler, config: ProviderConfig, payload: bytes
    ) -> None:
        """A correctly signed token must still carry a claims object."""
        token = jws.serialize_compact({"alg": "RS256", "kid": "rsa-1"}, payload, RSA_KEY)

        with pytest.raises(IdentityFetchError, match="claims are not a JSON object"):
            await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=token), config)

    @pytest.mark.parametrize("audience", [42, {"aud": "otari"}, ["other"], []])
    async def test_refuses_an_id_token_whose_audience_is_not_a_string_or_array(
        self, handler: OidcIdentityHandler, config: ProviderConfig, audience: object
    ):
        """``aud`` is a string or an array of strings naming us (section 2).

        An oddly-typed ``aud``, or an array that does not name this client,
        must fail closed rather than being treated as "no audience to disagree
        with".
        """
        with pytest.raises(IdentityFetchError, match=r"invalid a(ud|zp) claim"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", aud=audience)),
                config,
            )

    async def test_reports_a_malformed_header_as_an_identity_error(
        self, handler: OidcIdentityHandler, config: ProviderConfig
    ):
        """A non-string ``alg`` is refused before any key is fetched."""
        now = int(time.time())
        payload = {"iss": ISSUER, "sub": "u-1", "aud": CLIENT_ID, "exp": now + 300, "iat": now, "at_hash": "x"}
        token = f"{_b64(json.dumps({'alg': 5}).encode())}.{_b64(json.dumps(payload).encode())}.signature"

        with pytest.raises(IdentityFetchError, match="signing algorithm that is not accepted"):
            await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=token), config)

    async def test_error_text_is_ours_not_the_validators(self, handler: OidcIdentityHandler, config: ProviderConfig):
        """A joserfc rewording must not change the user-facing contract."""
        with pytest.raises(IdentityFetchError) as excinfo:
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(iss="https://evil.example")), config
            )

        assert str(excinfo.value) == "OpenID ID token has an invalid iss claim"

    @pytest.mark.parametrize("subject", [123, "", ["u-1"]])
    async def test_reports_a_malformed_id_token_subject_as_such(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock, subject: object
    ):
        """A non-string ``sub`` is a malformed ID token, not a userinfo disagreement."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})

        with pytest.raises(TokenValidationError, match="ID token has an invalid sub claim") as exc_info:
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub=subject)), config
            )
        assert exc_info.value.reason is TokenValidationReason.CLAIMS

    async def test_refuses_when_there_is_no_userinfo_endpoint_and_no_id_token(self, config: ProviderConfig):
        """With neither document, nothing names a subject."""
        handler = identity_handler(metadata(userinfo_url=None))

        with pytest.raises(IdentityFetchError, match="no subject"):
            await handler.fetch_identity(IdentityMaterial(access_token="access"), config)

    @pytest.mark.filterwarnings("ignore:EdDSA is deprecated:joserfc.errors.SecurityWarning")
    async def test_accepts_an_eddsa_token_with_a_sha512_at_hash(
        self, handler: OidcIdentityHandler, config: ProviderConfig, httpx_mock: HTTPXMock
    ):
        """EdDSA names no hash of its own; the ``at_hash`` uses SHA-512 (Core section 3.1.3.6)."""
        httpx_mock.add_response(url=USERINFO_URL, json={"sub": "u-1"})
        at_hash = _b64(hashlib.sha512(b"access").digest()[:32])

        identity = await handler.fetch_identity(
            IdentityMaterial(access_token="access", id_token=id_token(alg="EdDSA", sub="u-1", at_hash=at_hash)),
            config,
        )

        assert identity.subject == "u-1"

    @pytest.mark.filterwarnings("ignore:EdDSA is deprecated:joserfc.errors.SecurityWarning")
    async def test_refuses_an_eddsa_token_with_the_wrong_at_hash(
        self, handler: OidcIdentityHandler, config: ProviderConfig
    ):
        """The EdDSA path still verifies the binding rather than skipping it."""
        with pytest.raises(IdentityFetchError, match="invalid at_hash claim"):
            await handler.fetch_identity(
                IdentityMaterial(
                    access_token="access", id_token=id_token(alg="EdDSA", sub="u-1", at_hash=_at_hash("access"))
                ),
                config,
            )

    async def test_refuses_a_non_string_azp(self, handler: OidcIdentityHandler, config: ProviderConfig):
        """A present-but-untyped ``azp`` is a claim that cannot be checked, so it fails closed."""
        with pytest.raises(IdentityFetchError, match=r"invalid azp claim"):
            await handler.fetch_identity(
                IdentityMaterial(access_token="access", id_token=id_token(sub="u-1", azp=42)),
                config,
            )

    async def test_refuses_a_config_naming_no_issuer(self, handler: OidcIdentityHandler, config: ProviderConfig):
        """Section 3.1.3.7 step 2 makes ``iss`` a MUST; an issuer-less config has nothing to check against."""
        issuerless = config.model_copy(update={"issuer": None})

        with pytest.raises(ConfigurationError, match="names no issuer"):
            await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=id_token()), issuerless)

    @pytest.mark.parametrize("with_id_token", [True, False])
    async def test_refuses_a_config_for_another_issuer_before_any_request(
        self, handler: OidcIdentityHandler, httpx_mock: HTTPXMock, with_id_token: bool
    ) -> None:
        """A handler for one issuer never sends another issuer's access token to its userinfo endpoint."""
        other_issuer = "https://other.example.com"
        other = preset(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(issuer=other_issuer, userinfo_url=f"{other_issuer}/userinfo"),
        )
        material = IdentityMaterial(
            access_token="access",
            id_token=id_token(iss=other_issuer) if with_id_token else None,
        )

        with pytest.raises(ConfigurationError, match="different issuer"):
            await handler.fetch_identity(material, other)

        assert httpx_mock.get_requests() == []

    async def test_validates_against_the_config_not_the_handler(self, handler: OidcIdentityHandler):
        """Issuer and client id come from the config, so the pair cannot disagree."""
        other = preset(
            client_id="another-client",
            client_secret=CLIENT_SECRET,
            scopes=[],
            metadata=metadata(userinfo_url=None),
        )

        with pytest.raises(IdentityFetchError, match="invalid aud claim"):
            await handler.fetch_identity(IdentityMaterial(access_token="access", id_token=id_token()), other)


class TestBearerError:
    """Test how the parser reads the ``error`` code of a ``WWW-Authenticate`` header's ``Bearer`` challenge."""

    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ('Bearer error="insufficient_scope", scope="openid profile"', "insufficient_scope"),
            ("Bearer error=insufficient_scope", "insufficient_scope"),
            ('bearer realm="x", ERROR = "insufficient_scope"', "insufficient_scope"),
            ('Basic realm="x", Bearer error="insufficient_scope"', "insufficient_scope"),
            ('Negotiate abc==, Bearer error="insufficient_scope"', "insufficient_scope"),
            ('Bearer ,, error="insufficient_scope",', "insufficient_scope"),
            (', Bearer error="insufficient_scope"', "insufficient_scope"),
            ('Bearer error="insufficient\\_scope"', "insufficient_scope"),
            ('Bearer error="insufficient_scope", error_description="needs \u2192 scope"', "insufficient_scope"),
            ('Bearer realm="x"', None),
            ("Bearer", None),
            ("", None),
        ],
    )
    def test_reads_the_code_from_a_well_formed_header(self, header: str, expected: str | None) -> None:
        """A well-formed header gives its ``Bearer`` error code, or ``None`` when it has none."""
        assert _bearer_error(header) == expected

    @pytest.mark.parametrize("code", NEAR_MISS_SCOPE_CODES)
    def test_a_near_miss_code_is_returned_unchanged(self, code: str) -> None:
        """A near-miss code is returned exactly as sent."""
        assert _bearer_error(f'Bearer error="{code}"') == code

    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ('Bearer suberror="insufficient_scope"', None),
            ('Bearer error="invalid_token", error_description="not error=insufficient_scope"', "invalid_token"),
            ('Basic error="insufficient_scope"', None),
        ],
    )
    def test_only_the_bearer_error_parameter_supplies_the_code(self, header: str, expected: str | None) -> None:
        """Another parameter, another parameter's value, or another scheme's challenge never supplies the code."""
        assert _bearer_error(header) == expected

    @pytest.mark.parametrize(
        "header",
        [
            'Bearer abc==, error="insufficient_scope"',
            'Bearer,error="insufficient_scope"',
            'Bearer realm="x" error="insufficient_scope"',
            'Bearer realm="x"error="insufficient_scope"',
            'Bearer error="insufficient_scope" Basic',
            'Bearer error="insufficient_scope", @@@',
            'Bearer error="insufficient_scope", error="insufficient_scope"',
            'Bearer error="insufficient_scope", Bearer error="insufficient_scope"',
            'Bearer\nerror="insufficient_scope"',
            'Bearer\u00a0error="insufficient_scope"',
            'Bearer \terror="insufficient_scope"',
            'Bearer error="insufficient_scope\n"',
            'error="insufficient_scope"',
            'Bearer error="insufficient_scope',
        ],
    )
    def test_a_malformed_header_gives_no_code(self, header: str) -> None:
        """A header that does not parse in full is never read as a scope refusal."""
        assert _bearer_error(header) is None
