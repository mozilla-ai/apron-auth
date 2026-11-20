from __future__ import annotations

import asyncio
import json
import logging
import time
import traceback

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth._discovery import IssuerNotDeclaredError
from apron_auth.client import OAuthClient
from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityNotSupportedError,
    IssuerValidationError,
    McpDiscoveryError,
    McpRegistrationError,
    OAuthError,
)
from apron_auth.mcp import (
    _asm_candidates,
    _falls_back_to_origin,
    _honor_registered_auth_method,
    _is_blocked_host,
    _MetadataFault,
    _MetadataOutcome,
    _prm_candidates,
    _reported_outcome,
    _secret_agrees,
    _select_auth_method,
    _validate_url,
    cimd_client_id,
    discover,
    register_client,
    to_provider_config,
)
from apron_auth.models import (
    ApplicationType,
    AuthorizationCallback,
    ClientRegistration,
    FreshTokenSet,
    IdentityMaterial,
    IdentityProfile,
    OAuthPendingState,
    ProviderConfig,
    RequestLimits,
    SecretToken,
    ServerMetadata,
    TokenEndpointAuthMethod,
)

_REGISTER_URL = "https://auth.example.com/register"
_REDIRECT_URI = "https://app.example.com/callback"
_LEAKED_SECRET = "top-secret-value"  # pragma: allowlist secret

_PRM_ROOT = "https://mcp.example.com/.well-known/oauth-protected-resource"
_PRM_PATH = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
_ASM_ROOT = "https://auth.example.com/.well-known/oauth-authorization-server"
_ASM_OIDC = "https://auth.example.com/.well-known/openid-configuration"
_ORIGIN = "https://mcp.example.com"
_ORIGIN_ASM = "https://mcp.example.com/.well-known/oauth-authorization-server"
_ORIGIN_OIDC = "https://mcp.example.com/.well-known/openid-configuration"


def _origin_asm_payload(**overrides: object) -> dict[str, object]:
    """Return an authorization server document an MCP server serves for its own origin."""
    payload = _asm_payload(
        issuer=_ORIGIN,
        authorization_endpoint=f"{_ORIGIN}/authorize",
        token_endpoint=f"{_ORIGIN}/token",
    )
    payload.update(overrides)
    return payload


def _prm_payload(**overrides: object) -> dict[str, object]:
    """Return a protected-resource document, which RFC 9728 requires to declare its resource identifier."""
    payload: dict[str, object] = {
        "resource": _ORIGIN,
        "authorization_servers": ["https://auth.example.com"],
    }
    payload.update(overrides)
    return payload


def _asm_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "scopes_supported": ["read", "write"],
    }
    payload.update(overrides)
    return payload


# What a caller's own hook puts in its message, which the library's refusal must not repeat.
_VALIDATOR_MESSAGE = "blocked by policy for tenant acme-42"
_FACTORY_MESSAGE = "no route to host 10.1.2.3 for tenant acme-42"


def _refusing_validator(url: str) -> None:
    """Refuse every URL the way a caller's own policy hook does, with its own text."""
    del url
    raise ValueError(_VALIDATOR_MESSAGE)


def _refusing_transport_factory(url: str) -> httpx.MockTransport:
    """Refuse to build a transport the way a caller's host policy does, with its own text."""
    del url
    raise RuntimeError(_FACTORY_MESSAGE)


def _crawling_transport(url: str) -> httpx.MockTransport:
    """Return a transport whose answer never arrives within any limit a test sets."""

    async def crawl(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json={})

    return httpx.MockTransport(crawl)


class TestToProviderConfig:
    def _meta(self, **overrides: object) -> ServerMetadata:
        defaults: dict[str, object] = {
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
            "code_challenge_methods": ["S256"],
            "token_endpoint_auth_methods": ["client_secret_post", "none"],
        }
        defaults.update(overrides)
        return ServerMetadata(**defaults)

    def test_result_is_provider_config(self) -> None:
        config = to_provider_config(self._meta(), ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert isinstance(config, ProviderConfig)

    def test_maps_endpoints(self) -> None:
        meta = self._meta(revocation_url="https://auth.example.com/revoke")
        config = to_provider_config(meta, ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert config.authorize_url == "https://auth.example.com/authorize"
        assert config.token_url == "https://auth.example.com/token"
        assert config.revocation_url == "https://auth.example.com/revoke"

    def test_confidential_client_uses_secret_post(self) -> None:
        config = to_provider_config(self._meta(), ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert config.token_endpoint_auth_method is TokenEndpointAuthMethod.CLIENT_SECRET_POST
        assert config.client_secret is not None

    def test_public_client_uses_none(self) -> None:
        config = to_provider_config(self._meta(), ClientRegistration(client_id="c"))
        assert config.token_endpoint_auth_method == "none"
        assert config.client_secret is None

    def test_confidential_client_uses_basic_when_only_basic_advertised(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=["client_secret_basic"])
        config = to_provider_config(meta, ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_confidential_client_defaults_basic_when_unadvertised(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=[])
        config = to_provider_config(meta, ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_raises_when_server_requires_unsupported_auth_method(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=["private_key_jwt"])
        with pytest.raises(ConfigurationError):
            to_provider_config(meta, ClientRegistration(client_id="c", client_secret=SecretStr("s")))

    def test_public_client_rejected_when_none_not_advertised(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=["client_secret_basic"])
        with pytest.raises(ConfigurationError):
            to_provider_config(meta, ClientRegistration(client_id="c"))

    def test_registered_method_overrides_advertised_derivation(self) -> None:
        # The server advertises only client_secret_post, but this client was
        # registered as client_secret_basic; the per-client registration wins.
        config = to_provider_config(
            self._meta(token_endpoint_auth_methods=["client_secret_post"]),
            ClientRegistration(
                client_id="c", client_secret=SecretStr("s"), token_endpoint_auth_method="client_secret_basic"
            ),
        )
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_registered_none_yields_public_client(self) -> None:
        config = to_provider_config(self._meta(), ClientRegistration(client_id="c", token_endpoint_auth_method="none"))
        assert config.token_endpoint_auth_method == "none"
        assert config.client_secret is None

    def test_registered_confidential_method_without_secret_raises(self) -> None:
        with pytest.raises(ConfigurationError):
            to_provider_config(
                self._meta(),
                ClientRegistration(client_id="c", token_endpoint_auth_method="client_secret_basic"),
            )

    def test_registered_none_with_secret_raises(self) -> None:
        # A public-client registration paired with a secret is contradictory;
        # emitting it would attach the secret to public-client requests.
        with pytest.raises(ConfigurationError):
            to_provider_config(
                self._meta(),
                ClientRegistration(client_id="c", client_secret=SecretStr("s"), token_endpoint_auth_method="none"),
            )

    def test_absent_registered_method_falls_back_to_derivation(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=["client_secret_basic"])
        config = to_provider_config(meta, ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_an_empty_secret_builds_a_public_client(self) -> None:
        """An empty secret states none, so a caller passing one builds a public client."""
        config = to_provider_config(self._meta(), ClientRegistration(client_id="c", client_secret=""))
        assert config.client_secret is None
        assert config.token_endpoint_auth_method is TokenEndpointAuthMethod.NONE

    def test_carries_the_registered_secret_onto_the_configuration(self) -> None:
        config = to_provider_config(
            self._meta(), ClientRegistration(client_id="c", client_secret=SecretStr("raw-secret"))
        )
        assert config.client_secret is not None
        assert config.client_secret.get_secret_value() == "raw-secret"

    def test_refuses_a_registration_secret_supplied_as_plain_text(self) -> None:
        """A registration a caller builds by hand holds its secret to the same rule as a configuration."""
        with pytest.raises(ConfigurationError) as caught:
            ClientRegistration(client_id="c", client_secret="raw-secret")  # ty: ignore[invalid-argument-type]

        assert "raw-secret" not in str(caught.value)
        assert "wrapped" in str(caught.value)

    def test_pkce_enabled_when_s256_supported(self) -> None:
        config = to_provider_config(
            self._meta(code_challenge_methods=["S256"]), ClientRegistration(client_id="c", client_secret=SecretStr("s"))
        )
        assert config.use_pkce is True

    def test_pkce_enabled_by_default_when_unadvertised(self) -> None:
        config = to_provider_config(
            self._meta(code_challenge_methods=[]), ClientRegistration(client_id="c", client_secret=SecretStr("s"))
        )
        assert config.use_pkce is True

    def test_pkce_disabled_when_s256_absent(self) -> None:
        config = to_provider_config(
            self._meta(code_challenge_methods=["plain"]),
            ClientRegistration(client_id="c", client_secret=SecretStr("s")),
        )
        assert config.use_pkce is False

    def test_scopes_and_redirect_passed(self) -> None:
        config = to_provider_config(
            self._meta(),
            ClientRegistration(client_id="c", client_secret=SecretStr("s")),
            scopes=["a", "b"],
            redirect_uri="https://app.example.com/cb",
        )
        assert config.scopes == ["a", "b"]
        assert config.redirect_uri == "https://app.example.com/cb"

    def test_issuer_and_iss_requirement_threaded_from_metadata(self) -> None:
        meta = self._meta(issuer="https://auth.example.com", iss_parameter_supported=True)
        config = to_provider_config(meta, ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert config.issuer == "https://auth.example.com"
        assert config.require_iss is True

    async def test_a_callback_without_iss_is_refused_against_a_discovered_issuer(self) -> None:
        """Discovery sets the requirement, so nothing is left for a caller to remember per call."""
        meta = self._meta(issuer="https://auth.example.com", iss_parameter_supported=True)
        config = to_provider_config(
            meta, ClientRegistration(client_id="c", client_secret=SecretStr("s")), redirect_uri=_REDIRECT_URI
        )
        client = OAuthClient(config)
        pending = OAuthPendingState(
            state="s-1", redirect_uri=_REDIRECT_URI, openid_requested=False, created_at=time.time()
        )

        with pytest.raises(IssuerValidationError):
            await client.exchange_code(
                AuthorizationCallback(code=SecretToken("auth-code"), state="s-1"), pending_state=pending
            )

    def test_issuer_absent_leaves_config_unbound(self) -> None:
        config = to_provider_config(self._meta(), ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert config.issuer is None
        assert config.require_iss is False

    def test_resource_threaded_from_metadata(self) -> None:
        meta = self._meta(resource="https://mcp.example.com/mcp")
        config = to_provider_config(meta, ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert config.resource == "https://mcp.example.com/mcp"

    def test_resource_absent_leaves_config_unbound(self) -> None:
        config = to_provider_config(self._meta(), ClientRegistration(client_id="c", client_secret=SecretStr("s")))
        assert config.resource is None

    def test_explicit_resource_overrides_metadata(self) -> None:
        meta = self._meta(resource="https://mcp.example.com")
        config = to_provider_config(
            meta,
            ClientRegistration(client_id="c", client_secret=SecretStr("s")),
            resource="https://mcp.example.com/server/mcp",
        )
        assert config.resource == "https://mcp.example.com/server/mcp"

    def test_cimd_url_client_id_yields_public_config(self) -> None:
        url = cimd_client_id("https://app.example.com/oauth/client-metadata.json")
        config = to_provider_config(self._meta(), ClientRegistration(client_id=url))
        assert config.client_id == "https://app.example.com/oauth/client-metadata.json"
        assert config.client_secret is None
        assert config.token_endpoint_auth_method == TokenEndpointAuthMethod.NONE

    def test_cimd_public_client_without_none_method_fails_fast(self) -> None:
        """A CIMD server offering only private_key_jwt (no 'none') must not yield a public config."""
        meta = self._meta(token_endpoint_auth_methods=["private_key_jwt"])
        with pytest.raises(ConfigurationError):
            to_provider_config(meta, ClientRegistration(client_id="https://app.example.com/c.json"))


class TestToProviderConfigIdentity:
    @pytest.fixture(
        params=[
            pytest.param(
                ("https://mcp.linear.app/authorize", "https://mcp.linear.app/token"),
                id="linear",
            ),
            pytest.param(
                ("https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token"),
                id="google",
            ),
        ]
    )
    def claimed_metadata(self, request: pytest.FixtureRequest) -> ServerMetadata:
        """Return metadata for an authorization server on a host that a built-in provider also serves."""
        authorize_url, token_url = request.param
        return ServerMetadata(authorize_url=authorize_url, token_url=token_url)

    def test_a_config_on_a_claimed_host_names_no_provider(self, claimed_metadata: ServerMetadata) -> None:
        """That provider's handler would send a token issued for the MCP server to its API."""
        config = to_provider_config(claimed_metadata, ClientRegistration(client_id="c"))

        assert config.provider is None

    async def test_a_client_without_a_handler_refuses_before_any_request(
        self, claimed_metadata: ServerMetadata, httpx_mock: HTTPXMock
    ) -> None:
        """The client raises the unsupported-identity error and sends nothing to the provider."""
        client = OAuthClient(to_provider_config(claimed_metadata, ClientRegistration(client_id="c")))

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(FreshTokenSet(access_token=SecretToken("access")))

        assert httpx_mock.get_requests() == []

    async def test_a_client_with_an_explicit_handler_establishes_identity(
        self, claimed_metadata: ServerMetadata
    ) -> None:
        """The explicit handler is the one source of identity for a config that names no provider."""

        class McpIdentityHandler:
            def __init__(self) -> None:
                self.calls: list[tuple[IdentityMaterial, ProviderConfig]] = []

            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                self.calls.append((material, config))
                return IdentityProfile(provider="mcp", subject="u-1")

        config = to_provider_config(claimed_metadata, ClientRegistration(client_id="c"))
        handler = McpIdentityHandler()
        client = OAuthClient(config, identity_handler=handler)

        identity = await client.fetch_identity(FreshTokenSet(access_token=SecretToken("access")))

        assert identity.identity_key() == ("mcp", "u-1")
        assert [(material.access_token.get_secret_value(), used_config) for material, used_config in handler.calls] == [
            ("access", config)
        ]


class TestSelectAuthMethod:
    @pytest.mark.parametrize(
        ("secret", "advertised", "expected"),
        [
            # A public client (no secret) is "none" when the server advertises
            # nothing or explicitly lists "none".
            (None, [], TokenEndpointAuthMethod.NONE),
            (None, ["none", "client_secret_post"], TokenEndpointAuthMethod.NONE),
            # A secret is the string it holds, so one holding nothing is a public client here too.
            (SecretStr(""), ["none"], TokenEndpointAuthMethod.NONE),
            (SecretStr("   "), ["none"], TokenEndpointAuthMethod.NONE),
            # A confidential client with nothing advertised defaults to basic (RFC 8414).
            (SecretStr("s"), [], TokenEndpointAuthMethod.CLIENT_SECRET_BASIC),
            # A confidential client honors the advertised method.
            (SecretStr("s"), ["client_secret_post"], TokenEndpointAuthMethod.CLIENT_SECRET_POST),
            (SecretStr("s"), ["client_secret_basic"], TokenEndpointAuthMethod.CLIENT_SECRET_BASIC),
            # When both are advertised, post wins by preference, regardless of order.
            (
                SecretStr("s"),
                ["client_secret_post", "client_secret_basic"],
                TokenEndpointAuthMethod.CLIENT_SECRET_POST,
            ),
            (
                SecretStr("s"),
                ["client_secret_basic", "client_secret_post"],
                TokenEndpointAuthMethod.CLIENT_SECRET_POST,
            ),
            # Unsupported methods are skipped in favor of a performable one.
            (
                SecretStr("s"),
                ["private_key_jwt", "client_secret_basic"],
                TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            ),
        ],
    )
    def test_returns_expected_method(self, secret: SecretStr | None, advertised: list[str], expected: str) -> None:
        assert _select_auth_method(secret, advertised) == expected

    def test_a_derived_method_is_the_enum_member(self) -> None:
        """A member equals its wire name, so only identity shows that the derived set holds members."""
        assert _select_auth_method(SecretStr("s"), ["client_secret_basic"]) is (
            TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
        )

    @pytest.mark.parametrize(
        "advertised",
        [
            ["private_key_jwt"],
            ["tls_client_auth", "private_key_jwt"],
            ["none"],  # a confidential client whose server accepts only public clients
        ],
    )
    def test_raises_when_confidential_methods_unavailable(self, advertised: list[str]) -> None:
        with pytest.raises(ConfigurationError):
            _select_auth_method(SecretStr("s"), advertised)

    @pytest.mark.parametrize(
        "advertised",
        [
            ["client_secret_basic"],
            ["client_secret_post", "client_secret_basic"],
            ["private_key_jwt"],
        ],
    )
    def test_public_client_raises_when_none_not_advertised(self, advertised: list[str]) -> None:
        with pytest.raises(ConfigurationError):
            _select_auth_method(None, advertised)

    def test_registered_method_wins_over_advertised(self) -> None:
        # The advertised set would derive post; the registered method wins.
        method = _select_auth_method(
            SecretStr("s"), ["client_secret_post"], registered=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
        )
        assert method == TokenEndpointAuthMethod.CLIENT_SECRET_BASIC


class TestSecretAgrees:
    @pytest.mark.parametrize(
        ("method", "secret", "agrees"),
        [
            (TokenEndpointAuthMethod.NONE, None, True),
            (TokenEndpointAuthMethod.NONE, SecretStr("s"), False),
            (TokenEndpointAuthMethod.CLIENT_SECRET_POST, SecretStr("s"), True),
            (TokenEndpointAuthMethod.CLIENT_SECRET_POST, None, False),
            (TokenEndpointAuthMethod.CLIENT_SECRET_BASIC, SecretStr("s"), True),
            (TokenEndpointAuthMethod.CLIENT_SECRET_BASIC, None, False),
        ],
    )
    def test_a_public_method_agrees_with_no_secret_and_any_other_with_one(
        self, method: TokenEndpointAuthMethod, secret: SecretStr | None, agrees: bool
    ) -> None:
        assert _secret_agrees(method, secret) is agrees


class TestHonorRegisteredAuthMethod:
    @pytest.mark.parametrize(
        ("registered", "secret"),
        [
            (TokenEndpointAuthMethod.NONE, None),
            (TokenEndpointAuthMethod.CLIENT_SECRET_POST, SecretStr("s")),
            (TokenEndpointAuthMethod.CLIENT_SECRET_BASIC, SecretStr("s")),
        ],
    )
    def test_returns_performable_method(self, registered: TokenEndpointAuthMethod, secret: SecretStr | None) -> None:
        assert _honor_registered_auth_method(registered, secret) is registered

    @pytest.mark.parametrize(
        ("registered", "secret"),
        [
            # A confidential method with no secret to send it.
            (TokenEndpointAuthMethod.CLIENT_SECRET_POST, None),
            (TokenEndpointAuthMethod.CLIENT_SECRET_BASIC, None),
            # A public client (none) must not carry a secret.
            (TokenEndpointAuthMethod.NONE, SecretStr("s")),
        ],
    )
    def test_raises_when_the_secret_disagrees(
        self, registered: TokenEndpointAuthMethod, secret: SecretStr | None
    ) -> None:
        with pytest.raises(ConfigurationError):
            _honor_registered_auth_method(registered, secret)


class TestDiscover:
    async def test_happy_path_root_wellknown(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.authorize_url == "https://auth.example.com/authorize"
        assert meta.token_url == "https://auth.example.com/token"
        assert meta.code_challenge_methods == ["S256"]
        assert meta.scopes_supported == ["read", "write"]

    async def test_path_scoped_prm_preferred(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_PATH, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com/mcp")
        assert meta.token_url == "https://auth.example.com/token"

    async def test_prm_falls_back_to_root_after_404(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_PATH, status_code=404)
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com/mcp")
        assert meta.authorize_url == "https://auth.example.com/authorize"

    async def test_prm_falls_back_to_root_after_a_deeply_nested_body(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A body that nests too deeply to decode is skipped like any other body that cannot be read."""
        httpx_mock.add_response(url=_PRM_PATH, content=b"[" * 100_000 + b"]" * 100_000)
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        with caplog.at_level(logging.DEBUG, logger="apron_auth.mcp"):
            meta = await discover("https://mcp.example.com/mcp")
        assert meta.authorize_url == "https://auth.example.com/authorize"
        assert any(
            "protected resource metadata returned a body that could not be read" in message
            for message in caplog.messages
        )

    async def test_resource_metadata_hint_tried_first(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://mcp.example.com/custom-prm",
            json=_prm_payload(),
        )
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover(
            "https://mcp.example.com",
            resource_metadata_url="https://mcp.example.com/custom-prm",
        )
        assert meta.token_url == "https://auth.example.com/token"

    async def test_asm_oidc_fallback(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ASM_OIDC, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.authorize_url == "https://auth.example.com/authorize"

    async def test_an_outage_on_one_candidate_makes_discovery_retryable(self, httpx_mock: HTTPXMock) -> None:
        """A server error on the primary metadata URL is not hidden by the fallback's usual 404."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, status_code=503)
        httpx_mock.add_response(url=_ASM_OIDC, status_code=404)
        with pytest.raises(McpDiscoveryError, match="could not be fetched") as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is FailureKind.SERVER_ERROR
        assert exc_info.value.retryable is True

    @pytest.mark.parametrize(
        ("status", "kind", "fault"),
        [
            # Only a not-found status says the server serves no such document.
            (404, FailureKind.REJECTED, "is not published"),
            (410, FailureKind.REJECTED, "is not published"),
            # A refusal may guard a document that exists.
            # A redirect this library will not follow says nothing about one either.
            (403, FailureKind.REJECTED, "could not be fetched"),
            (302, FailureKind.REFUSED, "could not be fetched"),
        ],
    )
    async def test_a_status_on_every_candidate_names_what_it_showed(
        self, httpx_mock: HTTPXMock, status: int, kind: FailureKind, fault: str
    ) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, status_code=status)
        httpx_mock.add_response(url=_ASM_OIDC, status_code=status)
        with pytest.raises(McpDiscoveryError, match=fault) as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is kind
        assert exc_info.value.retryable is False

    async def test_an_unreadable_body_on_every_candidate_is_a_refusal(self, httpx_mock: HTTPXMock) -> None:
        """A document that answers but does not decode is told apart from one the server does not publish."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, content=b"not json")
        httpx_mock.add_response(url=_ASM_OIDC, json=["not", "an", "object"])
        with pytest.raises(McpDiscoveryError, match="is not a JSON object") as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is FailureKind.REFUSED
        assert exc_info.value.retryable is False

    async def test_an_outage_decides_over_a_candidate_that_answered(self, httpx_mock: HTTPXMock) -> None:
        """A corrupt document does not settle a fetch whose other candidate may still serve one."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, content=b"not json")
        httpx_mock.add_response(url=_ASM_OIDC, status_code=503)
        with pytest.raises(McpDiscoveryError, match="could not be fetched") as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is FailureKind.SERVER_ERROR
        assert exc_info.value.retryable is True

    async def test_a_not_found_naming_a_time_to_come_back_decides(self, httpx_mock: HTTPXMock) -> None:
        """It is read as temporary, so it decides over a corrupt document although it says least."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, content=b"not json")
        httpx_mock.add_response(url=_ASM_OIDC, status_code=404, headers={"Retry-After": "30"})
        with pytest.raises(McpDiscoveryError, match="is not published") as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is FailureKind.SERVER_ERROR
        assert exc_info.value.retryable is True

    @pytest.mark.parametrize(
        ("status", "content", "kind", "fault"),
        [
            # A body that answered but did not decode.
            pytest.param(200, b"not json", FailureKind.REFUSED, "is not a JSON object", id="unreadable"),
            # A refusal that may guard a document that exists.
            pytest.param(403, b"", FailureKind.REJECTED, "could not be fetched", id="refused"),
            # A redirect this library will not follow.
            pytest.param(302, b"", FailureKind.REFUSED, "could not be fetched", id="redirect"),
        ],
    )
    async def test_a_not_found_fallback_does_not_hide_what_an_earlier_candidate_showed(
        self, httpx_mock: HTTPXMock, status: int, content: bytes, kind: FailureKind, fault: str
    ) -> None:
        """A not-found says least about the document, so a candidate that showed more decides over it."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, status_code=status, content=content)
        httpx_mock.add_response(url=_ASM_OIDC, status_code=404)
        with pytest.raises(McpDiscoveryError, match=fault) as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is kind
        assert exc_info.value.retryable is False

    async def test_registration_and_revocation_surfaced(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(
            url=_ASM_ROOT,
            json=_asm_payload(
                registration_endpoint="https://auth.example.com/register",
                revocation_endpoint="https://auth.example.com/revoke",
            ),
        )
        meta = await discover("https://mcp.example.com")
        assert meta.registration_url == "https://auth.example.com/register"
        assert meta.revocation_url == "https://auth.example.com/revoke"

    async def test_missing_authorization_servers_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={})
        with pytest.raises(McpDiscoveryError):
            await discover("https://mcp.example.com")

    async def test_empty_authorization_server_entry_skipped(self, httpx_mock: HTTPXMock) -> None:
        """An empty first entry must not mask a valid later authorization server."""
        httpx_mock.add_response(
            url=_PRM_ROOT,
            json=_prm_payload(authorization_servers=["", "https://auth.example.com"]),
        )
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.token_url == "https://auth.example.com/token"

    async def test_skipped_candidate_logged_at_debug(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A skipped discovery candidate is logged at debug with a non-sensitive reason."""
        httpx_mock.add_response(url=_PRM_PATH, status_code=404)
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        with caplog.at_level(logging.DEBUG, logger="apron_auth.mcp"):
            await discover("https://mcp.example.com/mcp")
        assert any("protected resource metadata returned HTTP 404" in message for message in caplog.messages)

    async def test_issuer_and_iss_support_captured(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(
            url=_ASM_ROOT,
            json=_asm_payload(
                issuer="https://auth.example.com",
                authorization_response_iss_parameter_supported=True,
            ),
        )
        meta = await discover("https://mcp.example.com")
        assert meta.issuer == "https://auth.example.com"
        assert meta.iss_parameter_supported is True

    async def test_iss_support_default_when_absent(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.iss_parameter_supported is False

    async def test_issuer_absent_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """Metadata that declares no issuer cannot be bound to the authorization server it came from."""
        payload = _asm_payload()
        del payload["issuer"]
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=payload)
        with pytest.raises(McpDiscoveryError, match="declares no issuer") as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize("issuer", [None, 42, ""], ids=["null", "not a string", "empty"])
    async def test_issuer_that_is_not_a_name_is_refused_as_absent(self, httpx_mock: HTTPXMock, issuer: object) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload(issuer=issuer))
        with pytest.raises(McpDiscoveryError, match="declares no issuer"):
            await discover("https://mcp.example.com")

    @pytest.mark.parametrize(
        "issuer",
        [
            "https://evil.example.com",
            "http://auth.example.com",
            "https://auth.example.com/tenant",
            "https://auth.example.com/",
            "https://AUTH.example.com",
        ],
        ids=["other host", "other scheme", "other path", "terminating slash", "other case"],
    )
    async def test_issuer_that_is_not_the_authorization_server_is_refused(
        self, httpx_mock: HTTPXMock, issuer: str
    ) -> None:
        """The issuer must be identical to the identifier the metadata URL was built from, with no normalization."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload(issuer=issuer))
        with pytest.raises(McpDiscoveryError, match="declares a different issuer") as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is FailureKind.REFUSED
        assert isinstance(exc_info.value.__cause__, IssuerNotDeclaredError)

    async def test_declared_authorization_server_with_a_terminating_slash_must_match_exactly(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """A declared identifier with a terminating slash is compared as declared, not as the URL was built."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload(authorization_servers=["https://auth.example.com/"]))
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload(issuer="https://auth.example.com/"))
        meta = await discover("https://mcp.example.com")
        assert meta.issuer == "https://auth.example.com/"

    @pytest.mark.parametrize(
        "declared",
        [
            "https://auth.example.com/?tenant=b",
            "https://auth.example.com/#frag",
            "https://auth.example.com/?",
            "https://auth.example.com/#",
        ],
        ids=["query", "fragment", "empty query", "empty fragment"],
    )
    async def test_authorization_server_with_a_query_or_fragment_is_refused(
        self, httpx_mock: HTTPXMock, declared: str
    ) -> None:
        """The metadata URL drops a query and a fragment, so an identifier that carries one cannot be checked."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload(authorization_servers=[declared]))
        with pytest.raises(McpDiscoveryError, match="a query or a fragment"):
            await discover("https://mcp.example.com")

    async def test_malformed_authorization_server_is_a_discovery_error(self, httpx_mock: HTTPXMock) -> None:
        """An identifier that cannot be parsed is reported as a discovery error, not as the parser's own error."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload(authorization_servers=["https://[broken"]))
        with pytest.raises(McpDiscoveryError, match="malformed URL"):
            await discover("https://mcp.example.com")

    async def test_authorization_server_with_userinfo_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """Userinfo in the identifier would be sent as credentials with the metadata request."""
        declared = "https://user:pw@auth.example.com"  # pragma: allowlist secret
        seen: list[str] = []
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload(authorization_servers=[declared]))
        with pytest.raises(McpDiscoveryError, match=r"userinfo \(authorization server\)"):
            await discover("https://mcp.example.com", url_validator=seen.append)
        assert len(httpx_mock.get_requests()) == 1
        assert declared not in seen

    async def test_metadata_hint_with_userinfo_is_never_requested_or_shown_to_the_caller(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """A hint from a challenge header is refused before any request and before the caller's policy sees it."""
        hint = "https://user:pw@mcp.example.com/prm"  # pragma: allowlist secret
        seen: list[str] = []
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())

        await discover("https://mcp.example.com", resource_metadata_url=hint, url_validator=seen.append)

        assert hint not in seen
        assert all(str(request.url) != hint for request in httpx_mock.get_requests())

    async def test_declared_resource_with_userinfo_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """The declared resource is a document's value, so it is refused as the provider's fault."""
        resource = "https://user:pw@mcp.example.com/api"  # pragma: allowlist secret
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload(resource=resource))

        with pytest.raises(McpDiscoveryError, match=r"userinfo \(resource\)") as exc_info:
            await discover("https://mcp.example.com")

        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize(
        "member",
        ["authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"],
    )
    async def test_discovered_endpoint_with_userinfo_is_refused(self, httpx_mock: HTTPXMock, member: str) -> None:
        """The refusal names the member the document states, which is the name an operator reads there."""
        endpoint = "https://user:pw@auth.example.com/endpoint"  # pragma: allowlist secret
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload(**{member: endpoint}))

        with pytest.raises(McpDiscoveryError, match=rf"userinfo \({member}\)") as exc_info:
            await discover("https://mcp.example.com")

        assert exc_info.value.kind is FailureKind.REFUSED

    async def test_issuer_is_checked_before_any_other_member_is_read(self, httpx_mock: HTTPXMock) -> None:
        """A document with the wrong issuer is untrusted as a whole, so its endpoints never reach the URL policy."""
        seen: list[str] = []
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(
            url=_ASM_ROOT,
            json=_asm_payload(issuer="https://evil.example.com", authorization_endpoint="https://evil.example.com/a"),
        )
        with pytest.raises(McpDiscoveryError, match="declares a different issuer"):
            await discover("https://mcp.example.com", url_validator=seen.append)
        assert "https://evil.example.com/a" not in seen

    async def test_issuer_of_a_path_scoped_authorization_server_includes_the_path(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=_PRM_ROOT, json=_prm_payload(authorization_servers=["https://auth.example.com/tenant"])
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server/tenant",
            json=_asm_payload(issuer="https://auth.example.com/tenant"),
        )
        meta = await discover("https://mcp.example.com")
        assert meta.issuer == "https://auth.example.com/tenant"

    async def test_issuer_of_a_path_scoped_authorization_server_without_the_path_is_refused(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=_PRM_ROOT, json=_prm_payload(authorization_servers=["https://auth.example.com/tenant"])
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server/tenant",
            json=_asm_payload(issuer="https://auth.example.com"),
        )
        with pytest.raises(McpDiscoveryError, match="declares a different issuer"):
            await discover("https://mcp.example.com")

    async def test_identifier_with_a_terminating_slash_is_fetched_without_it(self, httpx_mock: HTTPXMock) -> None:
        """The slash is removed only to build the metadata URL; the declared identifier still has to match."""
        httpx_mock.add_response(
            url=_PRM_ROOT, json=_prm_payload(authorization_servers=["https://auth.example.com/tenant/"])
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server/tenant",
            json=_asm_payload(issuer="https://auth.example.com/tenant/"),
        )
        meta = await discover("https://mcp.example.com")
        assert meta.issuer == "https://auth.example.com/tenant/"

    async def test_identifier_with_a_terminating_slash_is_not_matched_without_it(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=_PRM_ROOT, json=_prm_payload(authorization_servers=["https://auth.example.com/tenant/"])
        )
        httpx_mock.add_response(
            url="https://auth.example.com/.well-known/oauth-authorization-server/tenant",
            json=_asm_payload(issuer="https://auth.example.com/tenant"),
        )
        with pytest.raises(McpDiscoveryError, match="declares a different issuer"):
            await discover("https://mcp.example.com")

    async def test_supports_cimd_captured(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(
            url=_ASM_ROOT,
            json=_asm_payload(client_id_metadata_document_supported=True),
        )
        meta = await discover("https://mcp.example.com")
        assert meta.supports_cimd is True

    async def test_supports_cimd_defaults_false_when_absent(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.supports_cimd is False

    async def test_supports_cimd_false_when_not_true(self, httpx_mock: HTTPXMock) -> None:
        """A non-boolean flag value must not be read as support."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload(client_id_metadata_document_supported="yes"))
        meta = await discover("https://mcp.example.com")
        assert meta.supports_cimd is False

    async def test_resource_identifier_captured(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload(resource="https://mcp.example.com/mcp"))
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.resource == "https://mcp.example.com/mcp"

    @pytest.mark.parametrize(
        ("resource", "expected"),
        [
            pytest.param(None, "declares no resource identifier", id="absent"),
            pytest.param(123, "declares no resource identifier", id="not-a-string"),
            pytest.param("", "declares no resource identifier", id="empty"),
            pytest.param("https://mcp.example.com#tag", "with a fragment", id="fragment"),
            pytest.param("/mcp", "is no absolute URI", id="relative"),
            pytest.param("https://[broken", "malformed resource identifier", id="malformed"),
            pytest.param("https://mcp.example.com/a b", "malformed resource identifier", id="a raw space"),
            pytest.param("https://mcp.example.com/%zz", "malformed resource identifier", id="a bad percent escape"),
        ],
    )
    async def test_a_resource_identifier_no_token_could_be_bound_to_is_refused(
        self, httpx_mock: HTTPXMock, resource: object, expected: str
    ) -> None:
        """RFC 9728 requires the field, and RFC 8707 requires a value a token's audience can state."""
        document: dict[str, object] = {"authorization_servers": ["https://auth.example.com"]}
        if resource is not None:
            document["resource"] = resource
        httpx_mock.add_response(url=_PRM_ROOT, json=document)
        with pytest.raises(McpDiscoveryError, match=expected) as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is FailureKind.REFUSED
        # The document is refused where it is read, so the authorization server is never fetched.
        assert [str(request.url) for request in httpx_mock.get_requests()] == [_PRM_ROOT]

    @pytest.mark.parametrize(
        "resource",
        [
            pytest.param("urn:example:mcp-service", id="urn"),
            pytest.param("https://mcp.example.com", id="https"),
        ],
    )
    async def test_a_resource_identifier_naming_no_host_is_still_an_absolute_uri(
        self, httpx_mock: HTTPXMock, resource: str
    ) -> None:
        """RFC 8707 asks for an absolute URI, which a URN is, so one is carried rather than refused."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload(resource=resource))
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.resource == resource
        assert to_provider_config(meta, ClientRegistration(client_id="c")).resource == resource

    async def test_missing_token_endpoint_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        payload = _asm_payload()
        del payload["token_endpoint"]
        httpx_mock.add_response(url=_ASM_ROOT, json=payload)
        with pytest.raises(McpDiscoveryError, match="missing an endpoint"):
            await discover("https://mcp.example.com")

    async def test_endpoint_with_an_unusable_port_is_a_discovery_error(self, httpx_mock: HTTPXMock) -> None:
        """A server-supplied endpoint with a bad port is refused at discovery, not at the first request to it."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload(token_endpoint="https://auth.example.com:99999/token"))
        with pytest.raises(McpDiscoveryError, match="malformed URL"):
            await discover("https://mcp.example.com")

    async def test_unfetchable_prm_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, status_code=500)
        with pytest.raises(McpDiscoveryError):
            await discover("https://mcp.example.com")

    async def test_non_https_server_url_rejected(self) -> None:
        """The server URL is the caller's own argument, so refusing it is a configuration fault."""
        with pytest.raises(ConfigurationError) as exc_info:
            await discover("http://mcp.example.com")
        assert exc_info.value.kind is FailureKind.CONFIGURATION

    async def test_non_https_authorization_server_rejected(self, httpx_mock: HTTPXMock) -> None:
        """The authorization server comes from a fetched document, so refusing it is a refusal."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload(authorization_servers=["http://auth.internal"]))
        with pytest.raises(McpDiscoveryError) as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is FailureKind.REFUSED

    async def test_loopback_server_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            await discover("https://127.0.0.1")

    async def test_localhost_server_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            await discover("https://localhost")

    async def test_link_local_metadata_ip_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            await discover("https://169.254.169.254")

    async def test_private_ip_authorization_server_rejected(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload(authorization_servers=["https://10.0.0.5"]))
        with pytest.raises(McpDiscoveryError):
            await discover("https://mcp.example.com")

    async def test_url_validator_invoked_and_rejection_wrapped(self) -> None:
        seen: list[str] = []

        def validator(url: str) -> None:
            seen.append(url)
            msg = "blocked by policy"
            raise ValueError(msg)

        with pytest.raises(ConfigurationError, match="caller policy") as exc_info:
            await discover("https://mcp.example.com", url_validator=validator)
        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert seen == ["https://mcp.example.com"]

    async def test_url_validator_rejection_of_a_derived_candidate_is_a_configuration_fault(self) -> None:
        """A well-known URL this library builds from the server URL belongs to the caller who passed it."""

        def validator(url: str) -> None:
            if url == _PRM_ROOT:
                msg = "blocked by policy"
                raise ValueError(msg)

        with pytest.raises(ConfigurationError, match="caller policy") as exc_info:
            await discover("https://mcp.example.com", url_validator=validator)
        assert exc_info.value.kind is FailureKind.CONFIGURATION

    async def test_url_validator_rejection_of_a_declared_endpoint_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """A document's endpoint the caller's policy rejects is a refusal, not a configuration fault."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())

        def validator(url: str) -> None:
            if url == "https://auth.example.com/token":
                msg = "blocked by policy"
                raise ValueError(msg)

        with pytest.raises(McpDiscoveryError, match="caller policy") as exc_info:
            await discover("https://mcp.example.com", url_validator=validator)
        assert exc_info.value.kind is FailureKind.REFUSED

    async def test_url_validator_oauth_error_propagates_unchanged(self) -> None:
        """The caller's own refusal reaches the caller as raised, carrying the kind it named."""

        def validator(url: str) -> None:
            del url
            msg = "refused by the caller"
            raise McpDiscoveryError(msg, kind=FailureKind.REJECTED)

        with pytest.raises(McpDiscoveryError, match="refused by the caller") as exc_info:
            await discover("https://mcp.example.com", url_validator=validator)
        assert exc_info.value.kind is FailureKind.REJECTED
        assert exc_info.value.__cause__ is None

    async def test_transport_factory_used_for_requests(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth-protected-resource" in request.url.path:
                return httpx.Response(200, json=_prm_payload())
            return httpx.Response(200, json=_asm_payload())

        def factory(url: str) -> httpx.MockTransport:
            calls.append(url)
            return httpx.MockTransport(handler)

        meta = await discover("https://mcp.example.com", transport_factory=factory)
        assert meta.token_url == "https://auth.example.com/token"
        assert calls

    async def test_caller_supplied_url_the_client_refuses_is_a_configuration_fault(self) -> None:
        """A URL the HTTP client refuses is a malformed URL, not a skipped candidate, and follows its source."""

        def handler(request: httpx.Request) -> httpx.Response:
            del request
            raise httpx.InvalidURL("refused")

        with pytest.raises(ConfigurationError, match="malformed URL") as exc_info:
            await discover("https://mcp.example.com", transport_factory=lambda _: httpx.MockTransport(handler))
        assert exc_info.value.kind is FailureKind.CONFIGURATION

    async def test_declared_url_the_client_refuses_is_a_discovery_error(self, httpx_mock: HTTPXMock) -> None:
        """A host only the HTTP client rejects is refused when a document named it, not blamed on the caller."""
        httpx_mock.add_response(
            url=_PRM_ROOT, json=_prm_payload(authorization_servers=["https://\x80\x80.example.com"])
        )
        with pytest.raises(McpDiscoveryError, match="malformed URL") as exc_info:
            await discover("https://mcp.example.com")
        assert exc_info.value.kind is FailureKind.REFUSED

    async def test_a_request_that_fails_in_transit_is_a_discovery_error(self) -> None:
        """A request the client sent and could not complete is an outage, whatever the URL's source."""

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        with pytest.raises(McpDiscoveryError, match="could not be fetched") as exc_info:
            await discover("https://mcp.example.com", transport_factory=lambda _: httpx.MockTransport(handler))
        assert exc_info.value.kind is FailureKind.UNREACHABLE
        assert exc_info.value.retryable is True

    async def test_a_host_the_client_cannot_resolve_follows_the_url_source(self) -> None:
        """A host only the HTTP client rejects reaches the request boundary, where the caller still owns it."""
        with pytest.raises(ConfigurationError, match="malformed URL") as exc_info:
            await discover("https://\x80\x80.example.com")
        assert exc_info.value.kind is FailureKind.CONFIGURATION

    async def test_an_authority_the_client_cannot_read_is_refused_before_any_request(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """The origin is built from an authority the HTTP client accepted, so one it refuses never reaches it.

        An IPvFuture literal is the case the two parsers read differently: the URL parser reads a host
        inside the brackets, and the HTTP client reads no host at all.
        """
        with pytest.raises(ConfigurationError, match="malformed URL") as exc_info:
            await discover("https://[v1.fe80]")
        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert not httpx_mock.get_requests()


class TestAServerThatPublishesNoProtectedResourceMetadata:
    """Test the origin fallback for a server built to an MCP revision that predates RFC 9728."""

    async def test_the_origin_is_read_as_the_authorization_server(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=_origin_asm_payload())
        meta = await discover(_ORIGIN)
        assert meta.authorize_url == f"{_ORIGIN}/authorize"
        assert meta.token_url == f"{_ORIGIN}/token"
        assert meta.issuer == _ORIGIN

    async def test_the_path_is_discarded_before_the_origin_is_tried(self, httpx_mock: HTTPXMock) -> None:
        """RFC 8414 locates the document under the origin, so the MCP server's own path plays no part."""
        httpx_mock.add_response(url=_PRM_PATH, status_code=404)
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=_origin_asm_payload())
        meta = await discover(f"{_ORIGIN}/mcp")
        assert meta.token_url == f"{_ORIGIN}/token"

    async def test_the_openid_location_at_the_origin_is_still_tried(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_OIDC, json=_origin_asm_payload())
        meta = await discover(_ORIGIN)
        assert meta.token_url == f"{_ORIGIN}/token"

    async def test_a_document_declaring_no_issuer_ends_discovery(self, httpx_mock: HTTPXMock) -> None:
        payload = _origin_asm_payload()
        del payload["issuer"]
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=payload)
        with pytest.raises(McpDiscoveryError, match="declares no issuer"):
            await discover(_ORIGIN)

    async def test_a_host_spelled_in_another_case_names_the_same_origin(self, httpx_mock: HTTPXMock) -> None:
        """A host is compared without case (RFC 3986 section 3.2.2), so its spelling is no issuer mismatch."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=_origin_asm_payload())
        meta = await discover("https://MCP.Example.com")
        assert meta.issuer == _ORIGIN

    async def test_an_ipv6_host_keeps_the_brackets_its_authority_needs(self, httpx_mock: HTTPXMock) -> None:
        """An address literal is read without its brackets and written back inside them."""
        origin = "https://[2606:4700::1]"
        httpx_mock.add_response(url=f"{origin}/.well-known/oauth-protected-resource", status_code=404)
        httpx_mock.add_response(
            url=f"{origin}/.well-known/oauth-authorization-server",
            json=_asm_payload(
                issuer=origin,
                authorization_endpoint=f"{origin}/authorize",
                token_endpoint=f"{origin}/token",
            ),
        )
        meta = await discover(origin)
        assert meta.issuer == origin

    async def test_the_schemes_default_port_is_no_part_of_the_origin(self, httpx_mock: HTTPXMock) -> None:
        """A stated port that the scheme makes default names the same server (RFC 3986 section 3.2.3)."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=_origin_asm_payload())
        meta = await discover("https://mcp.example.com:443")
        assert meta.issuer == _ORIGIN

    async def test_the_origin_identifier_reaches_the_callers_policy(self, httpx_mock: HTTPXMock) -> None:
        """The identifier is checked before it is used, as a declared one is."""
        seen: list[str] = []
        httpx_mock.add_response(url=_PRM_PATH, status_code=404)
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=_origin_asm_payload())
        await discover(f"{_ORIGIN}/mcp", url_validator=seen.append)
        assert _ORIGIN in seen

    async def test_an_empty_hint_names_no_document(self, httpx_mock: HTTPXMock) -> None:
        """A challenge parameter that stated nothing adds no candidate, so it names no document either."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=_origin_asm_payload())
        meta = await discover(_ORIGIN, resource_metadata_url="")
        assert meta.token_url == f"{_ORIGIN}/token"

    @pytest.mark.parametrize(
        "declared",
        [
            pytest.param(_ORIGIN, id="the same spelling"),
            pytest.param(f"{_ORIGIN}/", id="a terminating slash"),
            pytest.param(f"{_ORIGIN}:443", id="the port HTTPS makes default"),
            pytest.param("https://MCP.Example.com", id="another case"),
        ],
    )
    async def test_any_spelling_of_the_origin_names_it(self, httpx_mock: HTTPXMock, declared: str) -> None:
        """An origin is a scheme, a host and an effective port, so its spelling is no issuer mismatch."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=_origin_asm_payload(issuer=declared))
        meta = await discover(_ORIGIN)
        assert meta.issuer == declared

    @pytest.mark.parametrize(
        "declared",
        [
            pytest.param("https://evil.example.com", id="another host"),
            pytest.param(f"{_ORIGIN}:8443", id="a port the scheme does not make default"),
            pytest.param("http://mcp.example.com", id="another scheme"),
            pytest.param(f"{_ORIGIN}/tenant", id="a path below the root"),
            pytest.param(f"{_ORIGIN}/;tenant=blue", id="a parameter on the root path"),
            pytest.param(f"{_ORIGIN}?tenant=1", id="a query"),
            pytest.param(f"{_ORIGIN}#tenant", id="a fragment"),
            pytest.param(f"{_ORIGIN}/?", id="an empty query"),
            pytest.param(f"{_ORIGIN}/#", id="an empty fragment"),
            pytest.param("https://user:pw@mcp.example.com", id="a credential"),  # pragma: allowlist secret
            pytest.param(f"{_ORIGIN}:99999", id="a port out of range"),
        ],
    )
    async def test_an_identifier_stating_more_than_the_origin_ends_discovery(
        self, httpx_mock: HTTPXMock, declared: str
    ) -> None:
        """Anything the origin does not state names another server, or something under this one."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=_origin_asm_payload(issuer=declared))
        with pytest.raises(McpDiscoveryError, match="declares a different issuer") as exc_info:
            await discover(_ORIGIN)
        assert exc_info.value.kind is FailureKind.REFUSED
        assert declared not in str(exc_info.value)

    async def test_an_internationalized_host_names_the_host_the_request_reaches(self, httpx_mock: HTTPXMock) -> None:
        """A name is dialed in its ASCII form, which is the form a server declares as its issuer."""
        ascii_origin = "https://xn--bcher-kva.example"
        httpx_mock.add_response(url=f"{ascii_origin}/.well-known/oauth-protected-resource", status_code=404)
        httpx_mock.add_response(
            url=f"{ascii_origin}/.well-known/oauth-authorization-server",
            json=_asm_payload(
                issuer=ascii_origin,
                authorization_endpoint=f"{ascii_origin}/authorize",
                token_endpoint=f"{ascii_origin}/token",
            ),
        )
        meta = await discover("https://b\u00fccher.example")
        assert meta.issuer == ascii_origin

    async def test_an_ipv4_literal_needs_no_brackets(self, httpx_mock: HTTPXMock) -> None:
        """Only an IPv6 literal is written inside brackets, so an IPv4 one must not gain any."""
        origin = "https://1.1.1.1"
        httpx_mock.add_response(url=f"{origin}/.well-known/oauth-protected-resource", status_code=404)
        httpx_mock.add_response(
            url=f"{origin}/.well-known/oauth-authorization-server",
            json=_asm_payload(
                issuer=origin,
                authorization_endpoint=f"{origin}/authorize",
                token_endpoint=f"{origin}/token",
            ),
        )
        meta = await discover(origin)
        assert meta.issuer == origin

    async def test_an_address_literal_names_the_address_not_its_spelling(self, httpx_mock: HTTPXMock) -> None:
        """One address has many spellings, and all of them name the same server (RFC 5952)."""
        origin = "https://[2606:4700::1]"
        httpx_mock.add_response(url=f"{origin}/.well-known/oauth-protected-resource", status_code=404)
        httpx_mock.add_response(
            url=f"{origin}/.well-known/oauth-authorization-server",
            json=_asm_payload(
                issuer="https://[2606:4700:0:0:0:0:0:1]",
                authorization_endpoint=f"{origin}/authorize",
                token_endpoint=f"{origin}/token",
            ),
        )
        meta = await discover(origin)
        assert meta.issuer == "https://[2606:4700:0:0:0:0:0:1]"

    async def test_a_hint_leaves_the_server_read_as_a_current_one(self, httpx_mock: HTTPXMock) -> None:
        """A caller that relayed a protected-resource URL names a document, so no fallback applies."""
        httpx_mock.add_response(url=f"{_ORIGIN}/custom-prm", status_code=404)
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        with pytest.raises(McpDiscoveryError, match="protected resource metadata is not published"):
            await discover(_ORIGIN, resource_metadata_url=f"{_ORIGIN}/custom-prm")

    async def test_an_outage_on_a_candidate_stops_the_fallback(self, httpx_mock: HTTPXMock) -> None:
        """A server error says nothing about whether the document exists, unlike a not-found."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=503)
        with pytest.raises(McpDiscoveryError, match="could not be fetched") as exc_info:
            await discover(_ORIGIN)
        assert exc_info.value.retryable is True

    async def test_a_throttle_answering_with_a_not_found_stops_the_fallback(self, httpx_mock: HTTPXMock) -> None:
        """A not-found naming a time to come back is a throttle, so it does not say the document is absent."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404, headers={"Retry-After": "30"})
        with pytest.raises(McpDiscoveryError, match="protected resource metadata is not published") as exc_info:
            await discover(_ORIGIN)
        assert exc_info.value.kind is FailureKind.SERVER_ERROR
        assert exc_info.value.retryable is True

    async def test_a_document_that_does_not_decode_stops_the_fallback(self, httpx_mock: HTTPXMock) -> None:
        """A body that answered and did not decode says the server serves the document, badly."""
        httpx_mock.add_response(url=_PRM_PATH, status_code=404)
        httpx_mock.add_response(url=_PRM_ROOT, content=b"not json")
        with pytest.raises(McpDiscoveryError, match="is not a JSON object"):
            await discover(f"{_ORIGIN}/mcp")

    async def test_an_absent_endpoint_stays_a_refusal(self, httpx_mock: HTTPXMock) -> None:
        """No endpoint is guessed from the origin, so a document that names none is refused."""
        payload = _origin_asm_payload()
        del payload["token_endpoint"]
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=payload)
        with pytest.raises(McpDiscoveryError, match="is missing an endpoint"):
            await discover(_ORIGIN)

    async def test_no_resource_indicator_is_invented(self, httpx_mock: HTTPXMock) -> None:
        """The resource identifier lives in the document that was not published, so there is none."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ORIGIN_ASM, json=_origin_asm_payload())
        meta = await discover(_ORIGIN)
        assert meta.resource is None

    async def test_the_origins_metadata_url_belongs_to_the_caller(self, httpx_mock: HTTPXMock) -> None:
        """The origin derives from server_url, so a policy refusing it faults the caller's configuration."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)

        def refuse_the_origin(url: str) -> None:
            if url.startswith(_ORIGIN_ASM):
                raise ValueError(_VALIDATOR_MESSAGE)

        with pytest.raises(ConfigurationError, match="refused a URL by caller policy") as exc_info:
            await discover(_ORIGIN, url_validator=refuse_the_origin)
        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert _VALIDATOR_MESSAGE not in str(exc_info.value)


class TestARelayedHintBelongsToTheServerThatChoseIt:
    """Test that the value a server put in a challenge is the server's, and that a bad one only loses its turn."""

    @pytest.mark.parametrize(
        "hint",
        [
            pytest.param("http://mcp.example.com/prm", id="not https"),
            pytest.param("https://169.254.169.254/prm", id="a host that is not globally reachable"),
            pytest.param("https://user:pw@mcp.example.com/prm", id="userinfo"),  # pragma: allowlist secret
            pytest.param("https://mcp.example.com:99999/prm", id="a port out of range"),
            pytest.param("https://[::1", id="malformed"),
        ],
    )
    async def test_a_refused_hint_leaves_the_well_known_locations_to_try(
        self, httpx_mock: HTTPXMock, hint: str
    ) -> None:
        """RFC 9728 makes the hint a hint, so one this library will not fetch loses its turn, not the discovery."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())

        meta = await discover("https://mcp.example.com", resource_metadata_url=hint)

        assert meta.token_url == "https://auth.example.com/token"

    async def test_a_refused_hint_is_logged_as_a_skipped_candidate(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())

        with caplog.at_level(logging.DEBUG, logger="apron_auth.mcp"):
            await discover("https://mcp.example.com", resource_metadata_url="http://mcp.example.com/prm")

        assert any("protected resource metadata" in message for message in caplog.messages)

    async def test_a_refused_hint_is_not_the_callers_fault_when_nothing_else_answers(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """A server could otherwise make this library report a configuration fault about a value it chose."""
        httpx_mock.add_response(url=_PRM_ROOT, status_code=404)

        with pytest.raises(McpDiscoveryError) as exc_info:
            await discover("https://mcp.example.com", resource_metadata_url="http://mcp.example.com/prm")

        assert not isinstance(exc_info.value, ConfigurationError)

    async def test_a_hint_the_callers_own_policy_refuses_loses_its_turn(self, httpx_mock: HTTPXMock) -> None:
        """A hook refusing one URL says nothing about the rest, and the hint is the one URL with a fallback."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        refused: list[str] = []

        def validator(url: str) -> None:
            if url == "https://mcp.example.com/prm":
                refused.append(url)
                raise ValueError(_VALIDATOR_MESSAGE)

        meta = await discover(
            "https://mcp.example.com", resource_metadata_url="https://mcp.example.com/prm", url_validator=validator
        )

        assert refused == ["https://mcp.example.com/prm"]
        assert meta.token_url == "https://auth.example.com/token"

    async def test_a_hint_the_callers_transport_refuses_loses_its_turn(self) -> None:
        """A DNS-pinning transport is the real defense, so a server naming an internal host must not end it."""

        def serve(request: httpx.Request) -> httpx.Response:
            if str(request.url) == _PRM_ROOT:
                return httpx.Response(200, json=_prm_payload())
            return httpx.Response(200, json=_asm_payload())

        def pinning_factory(url: str) -> httpx.MockTransport:
            if url == "https://internal.corp.example/prm":
                raise RuntimeError(_FACTORY_MESSAGE)
            return httpx.MockTransport(serve)

        meta = await discover(
            "https://mcp.example.com",
            resource_metadata_url="https://internal.corp.example/prm",
            transport_factory=pinning_factory,
        )

        assert meta.token_url == "https://auth.example.com/token"

    async def test_a_hooks_refusal_of_a_url_with_no_fallback_still_ends_discovery(self) -> None:
        """Only a hint has a fallback, so every other URL a hook refuses ends the fetch as it did."""
        with pytest.raises(OAuthError, match="caller policy"):
            await discover("https://mcp.example.com", url_validator=_refusing_validator)

    async def test_a_hooks_own_error_class_reaches_the_caller(self) -> None:
        """A hook raising one of this library's errors states its own kind, which must not be relabeled."""

        def refusing_factory(url: str) -> httpx.MockTransport:
            del url
            raise IdentityNotSupportedError("my own policy refused this host")

        with pytest.raises(IdentityNotSupportedError, match="my own policy"):
            await discover("https://mcp.example.com", transport_factory=refusing_factory)

    async def test_a_registration_url_stays_the_callers_own(self, httpx_mock: HTTPXMock) -> None:
        """The caller chose what to pass here, and one read by discovery was already checked when it was read."""
        del httpx_mock

        with pytest.raises(ConfigurationError) as exc_info:
            await register_client(
                "http://auth.example.com/register", redirect_uri="https://app.example.com/cb", client_name="app"
            )

        assert exc_info.value.kind is FailureKind.CONFIGURATION

    async def test_discovery_holds_a_declared_registration_endpoint_to_the_document_rules(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """That check is why a registration URL reaching the caller has already been validated once."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(
            url=_ASM_ROOT, json=_asm_payload(registration_endpoint="http://auth.example.com/register")
        )

        with pytest.raises(McpDiscoveryError, match=r"\(registration_endpoint\)") as exc_info:
            await discover("https://mcp.example.com")

        assert exc_info.value.kind is FailureKind.REFUSED


class TestACallerHookThatFailsIsReportedAsThisPhasesError:
    """Test that a caller's own hook failing is refused in MCP terms, and that its text is only chained."""

    async def test_a_transport_factory_failure_ends_discovery(self) -> None:
        with pytest.raises(McpDiscoveryError, match=r"could not open a connection") as exc_info:
            await discover("https://mcp.example.com", transport_factory=_refusing_transport_factory)

        assert _FACTORY_MESSAGE not in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert exc_info.value.kind is FailureKind.UNEXPECTED

    async def test_a_transport_factory_failure_ends_registration(self) -> None:
        with pytest.raises(McpRegistrationError, match=r"could not open a connection") as exc_info:
            await register_client(
                _REGISTER_URL,
                redirect_uri="https://app.example.com/cb",
                client_name="app",
                transport_factory=_refusing_transport_factory,
            )

        assert _FACTORY_MESSAGE not in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert exc_info.value.kind is FailureKind.UNEXPECTED

    async def test_a_validator_failure_ends_registration(self) -> None:
        """Which error class carries it follows from the URL's source, which this is not about."""
        with pytest.raises(OAuthError, match="caller policy") as exc_info:
            await register_client(
                _REGISTER_URL,
                redirect_uri="https://app.example.com/cb",
                client_name="app",
                url_validator=_refusing_validator,
            )

        assert _VALIDATOR_MESSAGE not in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, ValueError)


class TestTheGatingMetadataListsAreParsedStrictly:
    """Test that a malformed list gating a security decision is refused, not read as "not advertised"."""

    @pytest.mark.parametrize("key", ["code_challenge_methods_supported", "token_endpoint_auth_methods_supported"])
    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("S256", id="a string"),
            pytest.param(42, id="a number"),
            pytest.param({"S256": True}, id="an object"),
            pytest.param(["S256", 42], id="a list with a number"),
            pytest.param(["S256", None], id="a list with a null"),
            pytest.param([["S256"]], id="a list of lists"),
            pytest.param(None, id="an explicit null"),
        ],
    )
    async def test_a_malformed_value_is_refused(self, httpx_mock: HTTPXMock, key: str, value: object) -> None:
        """Read leniently, a malformed value becomes an empty list, which takes the permissive branch."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload(**{key: value}))

        with pytest.raises(McpDiscoveryError, match=f"malformed {key}") as exc_info:
            await discover("https://mcp.example.com")

        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize("key", ["code_challenge_methods_supported", "token_endpoint_auth_methods_supported"])
    async def test_an_absent_member_keeps_the_default(self, httpx_mock: HTTPXMock, key: str) -> None:
        """An absent member is not advertised, which the permissive branch is for."""
        payload = _asm_payload()
        del payload[key]
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=payload)

        meta = await discover("https://mcp.example.com")

        assert getattr(meta, "code_challenge_methods" if "challenge" in key else "token_endpoint_auth_methods") == []

    @pytest.mark.parametrize("value", [pytest.param("read", id="a string"), pytest.param(["read", 42], id="a list")])
    async def test_an_advisory_list_is_still_read_leniently(self, httpx_mock: HTTPXMock, value: object) -> None:
        """``scopes_supported`` gates nothing, so a provider malforming it must not fail discovery."""
        httpx_mock.add_response(url=_PRM_ROOT, json=_prm_payload())
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload(scopes_supported=value))

        meta = await discover("https://mcp.example.com")

        assert meta.scopes_supported == ([] if value == "read" else ["read"])


class TestIsBlockedHost:
    @pytest.mark.parametrize(
        ("host", "blocked"),
        [
            ("", True),
            ("localhost", True),
            ("app.localhost", True),
            ("127.0.0.1", True),
            ("::1", True),
            ("10.0.0.5", True),
            ("172.16.0.1", True),
            ("192.168.1.1", True),
            ("169.254.169.254", True),
            ("0.0.0.0", True),
            ("224.0.0.1", True),
            ("fe80::1", True),
            # Legacy numeric IPv4 forms resolve to loopback/private but
            # ipaddress.ip_address rejects them; they must still be blocked.
            ("2130706433", True),
            ("0x7f000001", True),
            ("017700000001", True),
            ("127.1", True),
            # Ranges that are neither private nor reserved, but not globally reachable either.
            ("100.64.0.1", True),
            ("192.0.2.1", True),
            ("198.18.0.1", True),
            ("240.0.0.1", True),
            ("::ffff:127.0.0.1", True),
            ("2001:db8::1", True),
            ("ff02::1", True),
            # Reserved space the registry counts as global in part.
            ("64:ff9b::a00:1", True),
            ("::2", True),
            ("fe00::1", True),
            # A trailing dot names the same host.
            ("localhost.", True),
            ("app.localhost.", True),
            ("127.0.0.1.", True),
            ("2130706433.", True),
            ("mcp.example.com", False),
            ("8.8.8.8", False),
            ("134744072", False),
            ("::ffff:8.8.8.8", False),
            ("2606:4700:4700::1111", False),
        ],
    )
    def test_classifies_host(self, host: str, blocked: bool) -> None:
        assert _is_blocked_host(host) is blocked


class TestPrmCandidateUrls:
    @pytest.mark.parametrize(
        ("hint", "server_url", "expected"),
        [
            (
                None,
                "https://mcp.example.com",
                ["https://mcp.example.com/.well-known/oauth-protected-resource"],
            ),
            (
                None,
                "https://mcp.example.com/",
                ["https://mcp.example.com/.well-known/oauth-protected-resource"],
            ),
            (
                None,
                "https://mcp.example.com/mcp",
                [
                    "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                    "https://mcp.example.com/.well-known/oauth-protected-resource",
                ],
            ),
            (
                "https://mcp.example.com/custom-prm",
                "https://mcp.example.com/mcp",
                [
                    "https://mcp.example.com/custom-prm",
                    "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                    "https://mcp.example.com/.well-known/oauth-protected-resource",
                ],
            ),
            # A parameter belongs to the path segment it follows, so the scoped location carries it.
            (
                None,
                "https://mcp.example.com/mcp;tenant=blue",
                [
                    "https://mcp.example.com/.well-known/oauth-protected-resource/mcp;tenant=blue",
                    "https://mcp.example.com/.well-known/oauth-protected-resource",
                ],
            ),
        ],
    )
    def test_candidate_order(self, hint: str | None, server_url: str, expected: list[str]) -> None:
        assert [candidate.url for candidate in _prm_candidates(hint, server_url)] == expected

    def test_only_the_hint_is_the_servers_value_and_the_only_hint(self) -> None:
        """The caller reads the hint out of a challenge, so its value is the server's choice."""
        candidates = _prm_candidates("https://mcp.example.com/custom-prm", "https://mcp.example.com/mcp")

        assert [candidate.caller_supplied for candidate in candidates] == [False, True, True]
        assert [candidate.is_hint for candidate in candidates] == [True, False, False]


class TestAsmCandidateUrls:
    @pytest.mark.parametrize(
        ("auth_server", "expected"),
        [
            (
                "https://auth.example.com",
                [
                    "https://auth.example.com/.well-known/oauth-authorization-server",
                    "https://auth.example.com/.well-known/openid-configuration",
                ],
            ),
            (
                "https://auth.example.com/tenant",
                [
                    "https://auth.example.com/.well-known/oauth-authorization-server/tenant",
                    "https://auth.example.com/.well-known/openid-configuration/tenant",
                    "https://auth.example.com/tenant/.well-known/openid-configuration",
                ],
            ),
            # A parameter belongs to the path segment it follows, so every location carries it.
            (
                "https://auth.example.com/tenant;region=eu",
                [
                    "https://auth.example.com/.well-known/oauth-authorization-server/tenant;region=eu",
                    "https://auth.example.com/.well-known/openid-configuration/tenant;region=eu",
                    "https://auth.example.com/tenant;region=eu/.well-known/openid-configuration",
                ],
            ),
        ],
    )
    def test_candidate_order(self, auth_server: str, expected: list[str]) -> None:
        candidates = _asm_candidates(auth_server, caller_supplied=False)
        assert [candidate.url for candidate in candidates] == expected

    def test_no_candidate_is_a_hint(self) -> None:
        """They differ only in where this library looks, so a refusal applies to all of them."""
        candidates = _asm_candidates("https://auth.example.com/tenant", caller_supplied=False)

        assert not any(candidate.is_hint for candidate in candidates)

    @pytest.mark.parametrize("caller_supplied", [True, False])
    def test_every_candidate_carries_the_identifiers_source(self, caller_supplied: bool) -> None:
        """A declared identifier faults the other side, and one derived from an argument faults the caller."""
        candidates = _asm_candidates("https://auth.example.com/tenant", caller_supplied=caller_supplied)

        assert all(candidate.caller_supplied is caller_supplied for candidate in candidates)


class TestReportedOutcome:
    _UNAVAILABLE = _MetadataOutcome(_MetadataFault.UNAVAILABLE, FailureKind.REJECTED)
    _UNPUBLISHED = _MetadataOutcome(_MetadataFault.UNPUBLISHED, FailureKind.REJECTED)
    _UNREADABLE = _MetadataOutcome(_MetadataFault.UNREADABLE, FailureKind.REFUSED)

    def test_a_retryable_outcome_decides_over_a_fault_that_outranks_it(self) -> None:
        """A candidate that failed retryably was never really tried, whatever another candidate showed."""
        outage = _MetadataOutcome(_MetadataFault.UNAVAILABLE, FailureKind.SERVER_ERROR)
        assert _reported_outcome([self._UNREADABLE, outage]) == outage
        assert _reported_outcome([outage, self._UNREADABLE]) == outage

    def test_a_retryable_outcome_decides_although_its_fault_says_least(self) -> None:
        """A not-found naming a time to come back carries the lowest rank and still decides."""
        comeback = _MetadataOutcome(_MetadataFault.UNPUBLISHED, FailureKind.SERVER_ERROR)
        assert _reported_outcome([self._UNREADABLE, comeback]) == comeback

    def test_the_fault_that_says_most_decides_among_the_rest(self) -> None:
        assert _reported_outcome([self._UNREADABLE, self._UNPUBLISHED]) == self._UNREADABLE
        assert _reported_outcome([self._UNPUBLISHED, self._UNREADABLE]) == self._UNREADABLE
        assert _reported_outcome([self._UNAVAILABLE, self._UNPUBLISHED]) == self._UNAVAILABLE
        assert _reported_outcome([self._UNPUBLISHED, self._UNAVAILABLE]) == self._UNAVAILABLE
        assert _reported_outcome([self._UNREADABLE, self._UNAVAILABLE]) == self._UNREADABLE

    def test_not_published_is_reported_only_where_every_candidate_showed_it(self) -> None:
        """A not-found everywhere is the one answer that says the server publishes no such document."""
        assert _reported_outcome([self._UNPUBLISHED, self._UNPUBLISHED]) == self._UNPUBLISHED

    def test_candidates_showing_one_fault_are_settled_by_the_order_they_were_tried(self) -> None:
        later = _MetadataOutcome(_MetadataFault.UNAVAILABLE, FailureKind.REFUSED)
        assert _reported_outcome([self._UNAVAILABLE, later]) == self._UNAVAILABLE

    def test_no_candidate_tried_says_nothing_about_the_document(self) -> None:
        assert _reported_outcome([]) == _MetadataOutcome(_MetadataFault.UNAVAILABLE, FailureKind.REFUSED)

    def test_every_fault_ranks_on_its_own(self) -> None:
        """A shared rank would let the order of the candidates decide again."""
        ranks = [fault.rank for fault in _MetadataFault]
        assert len(set(ranks)) == len(ranks)


class TestFallsBackToOrigin:
    """Test the rule that decides whether a missing protected-resource document reads the origin."""

    _UNPUBLISHED = _MetadataOutcome(_MetadataFault.UNPUBLISHED, FailureKind.REJECTED)

    def test_an_unpublished_document_with_no_hint_falls_back(self) -> None:
        assert _falls_back_to_origin(self._UNPUBLISHED, hinted=False) is True

    def test_a_hint_stops_the_fallback(self) -> None:
        assert _falls_back_to_origin(self._UNPUBLISHED, hinted=True) is False

    @pytest.mark.parametrize(
        "fault",
        [_MetadataFault.UNAVAILABLE, _MetadataFault.UNREADABLE],
    )
    def test_any_other_fault_stops_the_fallback(self, fault: _MetadataFault) -> None:
        assert _falls_back_to_origin(_MetadataOutcome(fault, FailureKind.REJECTED), hinted=False) is False

    def test_a_retryable_outcome_stops_the_fallback_although_the_fault_agrees(self) -> None:
        """A not-found carrying a time to come back is a throttle, and the fallback must not pass it."""
        comeback = _MetadataOutcome(_MetadataFault.UNPUBLISHED, FailureKind.SERVER_ERROR)
        assert _falls_back_to_origin(comeback, hinted=False) is False


class TestValidateUrl:
    @pytest.mark.parametrize("caller_supplied", [True, False])
    def test_https_public_host_passes(self, caller_supplied: bool) -> None:
        _validate_url("https://mcp.example.com/x", None, subject="server_url", caller_supplied=caller_supplied)

    @pytest.mark.parametrize(
        "url",
        [
            "http://mcp.example.com",
            "ftp://mcp.example.com",
            "https://127.0.0.1",
            "https://10.0.0.1/token",
            "https://169.254.169.254",
            "https://2130706433",
            "https://0x7f000001",
            "https://127.1",
            "https://100.64.0.1",
        ],
    )
    def test_rejects_unusable_url(self, url: str) -> None:
        """A URL a document named is refused, because the other side sent something this library will not fetch."""
        with pytest.raises(McpDiscoveryError) as exc_info:
            _validate_url(url, None, subject="server_url", caller_supplied=False)
        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize(
        "url",
        ["https://[::1", "https://mcp.example.com:99999/token", "https://mcp.example.com:port/token"],
        ids=["unclosed bracket", "port out of range", "port not a number"],
    )
    def test_rejects_malformed_url(self, url: str) -> None:
        """A URL that cannot be parsed, or whose port is out of range or not a number, is refused as malformed."""
        with pytest.raises(McpDiscoveryError, match="malformed URL") as exc_info:
            _validate_url(url, None, subject="server_url", caller_supplied=False)
        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize(
        "host",
        [
            pytest.param("localhost\u3002", id="the loopback name"),
            pytest.param("app\u3002localhost", id="a name under localhost"),
            pytest.param("127\u30020\u30020\u30021", id="the loopback address"),
            pytest.param("2130706433\u3002", id="a legacy numeric form"),
        ],
    )
    def test_rejects_a_non_public_host_written_with_another_dot(self, host: str) -> None:
        """The client reads each of these as a host it will not fetch, so the rule reads the host it dials.

        A document names this URL, so the other side chooses the spelling the rule is held to.
        """
        with pytest.raises(McpDiscoveryError, match="non-public host") as exc_info:
            _validate_url(f"https://{host}/x", None, subject="server_url", caller_supplied=False)
        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize(
        "url",
        ["https:///x", "https://", "https://?q=1"],
        ids=["an authority naming no host", "an authority and nothing else", "no host before the query"],
    )
    def test_rejects_a_url_naming_no_host_as_malformed(self, url: str) -> None:
        """A URL naming no host states no host the rule could hold, which is a malformed URL and not a host."""
        with pytest.raises(McpDiscoveryError, match="malformed URL") as exc_info:
            _validate_url(url, None, subject="server_url", caller_supplied=False)
        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize(
        "url",
        ["http://mcp.example.com", "https://127.0.0.1", "https://[::1"],
        ids=["not https", "non-public host", "malformed"],
    )
    def test_a_caller_supplied_url_is_a_configuration_fault(self, url: str) -> None:
        """The same conditions on the caller's own argument need a fix in the caller, not a retry."""
        with pytest.raises(ConfigurationError, match=r"\(server_url\)") as exc_info:
            _validate_url(url, None, subject="server_url", caller_supplied=True)
        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert exc_info.value.retryable is False

    def test_invokes_validator_when_url_is_acceptable(self) -> None:
        seen: list[str] = []
        _validate_url("https://mcp.example.com", seen.append, subject="server_url", caller_supplied=False)
        assert seen == ["https://mcp.example.com"]

    def test_wraps_validator_rejection(self) -> None:
        with pytest.raises(McpDiscoveryError, match=r"caller policy \(server_url\)"):
            _validate_url("https://mcp.example.com", _refusing_validator, subject="server_url", caller_supplied=False)

    def test_wraps_validator_rejection_of_a_caller_supplied_url_as_a_configuration_fault(self) -> None:
        with pytest.raises(ConfigurationError, match="caller policy") as exc_info:
            _validate_url("https://mcp.example.com", _refusing_validator, subject="server_url", caller_supplied=True)
        assert exc_info.value.kind is FailureKind.CONFIGURATION

    def test_a_validator_rejection_states_none_of_the_callers_own_text(self) -> None:
        """The caller's exception can carry detail it did not mean to surface, so only the chain holds it."""
        with pytest.raises(McpDiscoveryError) as exc_info:
            _validate_url("https://mcp.example.com", _refusing_validator, subject="server_url", caller_supplied=False)

        assert _VALIDATOR_MESSAGE not in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, ValueError)
        assert _VALIDATOR_MESSAGE in str(exc_info.value.__cause__)

    @pytest.mark.parametrize("caller_supplied", [True, False])
    def test_passes_through_validator_discovery_error(self, caller_supplied: bool) -> None:
        def validator(url: str) -> None:
            del url
            msg = "direct"
            raise McpDiscoveryError(msg, kind=FailureKind.REFUSED)

        with pytest.raises(McpDiscoveryError, match="direct") as exc_info:
            _validate_url("https://mcp.example.com", validator, subject="server_url", caller_supplied=caller_supplied)
        assert exc_info.value.__cause__ is None


class TestRegisterClient:
    async def test_returns_issued_credentials(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=_REGISTER_URL,
            status_code=201,
            json={
                "client_id": "generated-id",
                "client_secret": "generated-secret",  # pragma: allowlist secret
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
        reg = await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert reg.client_id == "generated-id"
        assert reg.client_secret is not None
        assert reg.client_secret.get_secret_value() == "generated-secret"
        assert reg.token_endpoint_auth_method == "client_secret_post"

    async def test_a_response_carrying_members_this_library_does_not_model_still_registers(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """A registration refuses a field it does not define, so the response must be read field by field."""
        httpx_mock.add_response(
            url=_REGISTER_URL,
            status_code=201,
            json={
                "client_id": "generated-id",
                "client_secret": "generated-secret",  # pragma: allowlist secret
                "token_endpoint_auth_method": "client_secret_post",
                "client_id_issued_at": 1799999999,
                "client_secret_expires_at": 0,
                "registration_access_token": "reg-token",  # pragma: allowlist secret
                "registration_client_uri": "https://as.example.com/register/generated-id",
            },
        )

        reg = await register_client(_REGISTER_URL, _REDIRECT_URI)

        assert reg.client_id == "generated-id"
        assert reg.client_secret is not None
        assert reg.client_secret.get_secret_value() == "generated-secret"

    async def test_sends_rfc7591_payload(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=200, json={"client_id": "x"})
        await register_client(_REGISTER_URL, _REDIRECT_URI, client_name="MyApp")
        request = httpx_mock.get_request()
        assert request is not None
        body = json.loads(request.content)
        assert body["client_name"] == "MyApp"
        assert body["redirect_uris"] == [_REDIRECT_URI]
        assert "authorization_code" in body["grant_types"]
        assert body["response_types"] == ["code"]

    async def test_public_client_registration_without_secret(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=_REGISTER_URL,
            status_code=201,
            json={"client_id": "pub", "token_endpoint_auth_method": "none"},
        )
        reg = await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert reg.client_secret is None
        assert reg.token_endpoint_auth_method == "none"

    async def test_auth_method_absent_when_response_omits_it(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "x"})
        reg = await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert reg.token_endpoint_auth_method is None

    @pytest.mark.parametrize("stated", ["private_key_jwt", "", 7, ["none"], {"method": "none"}])
    async def test_stated_method_this_library_cannot_perform_raises(
        self, httpx_mock: HTTPXMock, stated: object
    ) -> None:
        """The response states the method, so it is refused where the response is read, not at config time.

        The cases include a value a dictionary cannot key, because reading the method must refuse a
        JSON array or object rather than fail on the lookup.
        """
        httpx_mock.add_response(
            url=_REGISTER_URL,
            status_code=201,
            json={"client_id": "x", "token_endpoint_auth_method": stated},
        )
        with pytest.raises(McpRegistrationError, match="authentication method") as exc_info:
            await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize("stated", [7, ["s"], {"value": "s"}])
    async def test_stated_secret_this_library_cannot_use_raises(self, httpx_mock: HTTPXMock, stated: object) -> None:
        """The response states the secret, so it meets the test its client_id meets, where the response is read.

        A secret stating something that is not text could not be presented at the token endpoint.
        """
        httpx_mock.add_response(
            url=_REGISTER_URL,
            status_code=201,
            json={"client_id": "x", "client_secret": stated},
        )
        with pytest.raises(McpRegistrationError, match="client secret") as exc_info:
            await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize(
        "body",
        [
            # A public client declares none and carries no secret.
            {"client_id": "x", "client_secret": "s", "token_endpoint_auth_method": "none"},
            # Any other method is a confidential client, which has a secret to send.
            {"client_id": "x", "token_endpoint_auth_method": "client_secret_post"},
            {"client_id": "x", "token_endpoint_auth_method": "client_secret_basic"},
        ],
    )
    async def test_a_stated_method_that_contradicts_the_secret_raises(
        self, httpx_mock: HTTPXMock, body: dict[str, str]
    ) -> None:
        """The response states both, so the contradiction is refused where the response is read."""
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json=body)
        with pytest.raises(McpRegistrationError, match="contradicts") as exc_info:
            await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert exc_info.value.kind is FailureKind.REFUSED

    async def test_a_secret_stated_as_null_states_a_public_client(self, httpx_mock: HTTPXMock) -> None:
        """A member stated as null states no value, as an absent member does."""
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "pub", "client_secret": None})
        reg = await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert reg.client_secret is None

    async def test_an_empty_secret_states_a_public_client(self, httpx_mock: HTTPXMock) -> None:
        """An empty secret authenticates no client, so it states none, as an absent member does."""
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "pub", "client_secret": ""})
        reg = await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert reg.client_secret is None

    async def test_an_empty_secret_agrees_with_a_registered_public_method(self, httpx_mock: HTTPXMock) -> None:
        """The registered method and the secret agree, because an empty secret states no secret."""
        httpx_mock.add_response(
            url=_REGISTER_URL,
            status_code=201,
            json={"client_id": "pub", "client_secret": "", "token_endpoint_auth_method": "none"},
        )
        reg = await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert reg.client_secret is None
        assert reg.token_endpoint_auth_method is TokenEndpointAuthMethod.NONE

    async def test_an_empty_secret_contradicts_a_registered_confidential_method(self, httpx_mock: HTTPXMock) -> None:
        """A method that requires a secret has none to send, so the registration is refused."""
        httpx_mock.add_response(
            url=_REGISTER_URL,
            status_code=201,
            json={"client_id": "x", "client_secret": "", "token_endpoint_auth_method": "client_secret_post"},
        )
        with pytest.raises(McpRegistrationError, match="contradicts the secret") as exc_info:
            await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert exc_info.value.kind is FailureKind.REFUSED

    async def test_a_stated_method_is_the_enum_member(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=_REGISTER_URL,
            status_code=201,
            json={"client_id": "x", "token_endpoint_auth_method": "none"},
        )
        reg = await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert reg.token_endpoint_auth_method is TokenEndpointAuthMethod.NONE

    @pytest.mark.parametrize("body", [{"client_secret": "s"}, {"client_id": ""}, {"client_id": 7}])
    async def test_a_response_with_no_usable_client_id_raises(
        self, httpx_mock: HTTPXMock, body: dict[str, object]
    ) -> None:
        """An identifier that is absent, empty or not text names no client, so none of the three is usable."""
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json=body)
        with pytest.raises(McpRegistrationError, match="client_id") as exc_info:
            await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert exc_info.value.kind is FailureKind.REFUSED

    @pytest.mark.parametrize(
        "body",
        [
            # A malformed success body can carry client_secret while lacking client_id.
            {"client_secret": _LEAKED_SECRET},
            # A body refused for its stated method carries the issued secret too.
            # That refusal also sits next to a ValueError that repeats the stated method.
            {"client_id": "x", "client_secret": _LEAKED_SECRET, "token_endpoint_auth_method": "private_key_jwt"},
            # A secret this library cannot use can still hold one, nested where it cannot be read.
            {"client_id": "x", "client_secret": {"value": _LEAKED_SECRET}},
            # A method that contradicts the secret is refused with the secret in hand.
            {"client_id": "x", "client_secret": _LEAKED_SECRET, "token_endpoint_auth_method": "none"},
        ],
    )
    async def test_registration_error_never_leaks_client_secret(
        self, httpx_mock: HTTPXMock, body: dict[str, object]
    ) -> None:
        """A registration failure must not surface the issued secret anywhere.

        Neither the error's message nor its rendered traceback (which walks the
        ``__cause__``/``__context__`` chain) may expose it.
        """
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json=body)
        with pytest.raises(McpRegistrationError) as exc_info:
            await register_client(_REGISTER_URL, _REDIRECT_URI)
        rendered = "".join(
            traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
        )
        assert _LEAKED_SECRET not in str(exc_info.value)
        assert _LEAKED_SECRET not in rendered
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    @pytest.mark.parametrize("status", [400, 401, 403, 500])
    async def test_non_success_status_raises(self, httpx_mock: HTTPXMock, status: int) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=status, json={"error": "invalid_client_metadata"})
        with pytest.raises(McpRegistrationError):
            await register_client(_REGISTER_URL, _REDIRECT_URI)

    async def test_non_object_response_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json=["not", "a", "dict"])
        with pytest.raises(McpRegistrationError):
            await register_client(_REGISTER_URL, _REDIRECT_URI)

    async def test_deeply_nested_response_raises(self, httpx_mock: HTTPXMock) -> None:
        """A body that nests too deeply to decode is an unreadable response, not a raw recursion error."""
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, content=b"[" * 100_000 + b"]" * 100_000)
        with pytest.raises(McpRegistrationError, match="could not be read") as exc_info:
            await register_client(_REGISTER_URL, _REDIRECT_URI)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    @pytest.mark.parametrize("url", ["http://auth.example.com/register", "https://127.0.0.1/register"])
    async def test_unsafe_registration_url_rejected(self, url: str) -> None:
        """The registration URL is the caller's own argument, so refusing it is a configuration fault."""
        with pytest.raises(ConfigurationError) as exc_info:
            await register_client(url, _REDIRECT_URI)
        assert exc_info.value.kind is FailureKind.CONFIGURATION

    async def test_transport_factory_used(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            del request
            return httpx.Response(201, json={"client_id": "x"})

        def factory(url: str) -> httpx.MockTransport:
            calls.append(url)
            return httpx.MockTransport(handler)

        reg = await register_client(_REGISTER_URL, _REDIRECT_URI, transport_factory=factory)
        assert reg.client_id == "x"
        assert calls == [_REGISTER_URL]

    async def test_a_request_that_times_out_is_a_registration_error(self) -> None:
        """A request the client sent and could not complete is an outage, not a fault in the URL."""

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("boom", request=request)

        with pytest.raises(McpRegistrationError, match="timed out") as exc_info:
            await register_client(
                _REGISTER_URL, _REDIRECT_URI, transport_factory=lambda _: httpx.MockTransport(handler)
            )
        assert exc_info.value.kind is FailureKind.TIMEOUT
        assert exc_info.value.retryable is True

    async def test_url_the_client_refuses_is_a_configuration_fault(self) -> None:
        """The registration URL is the caller's, so a refusal at the request boundary is still their fault."""

        def handler(request: httpx.Request) -> httpx.Response:
            del request
            raise httpx.InvalidURL("refused")

        with pytest.raises(ConfigurationError, match=r"malformed URL \(registration_url\)") as exc_info:
            await register_client(
                _REGISTER_URL, _REDIRECT_URI, transport_factory=lambda _: httpx.MockTransport(handler)
            )
        assert exc_info.value.kind is FailureKind.CONFIGURATION

    @pytest.mark.parametrize("application_type", [ApplicationType.WEB, ApplicationType.NATIVE])
    async def test_explicit_application_type_included_in_payload(
        self, httpx_mock: HTTPXMock, application_type: ApplicationType
    ) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "x"})
        await register_client(_REGISTER_URL, _REDIRECT_URI, application_type=application_type)
        request = httpx_mock.get_request()
        assert request is not None
        assert json.loads(request.content)["application_type"] == application_type

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            "http://127.0.0.1:8080/callback",
            "http://localhost:8080/callback",
            "http://[::1]:8080/callback",
            "http://localhost.:8080/callback",
            "http://127.0.0.1.:8080/callback",
        ],
    )
    async def test_application_type_inferred_native_from_loopback_redirect(
        self, httpx_mock: HTTPXMock, redirect_uri: str
    ) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "x"})
        await register_client(_REGISTER_URL, redirect_uri)
        request = httpx_mock.get_request()
        assert request is not None
        assert json.loads(request.content)["application_type"] == "native"

    async def test_application_type_omitted_for_a_non_loopback_redirect(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "x"})
        await register_client(_REGISTER_URL, "https://app.example.com/callback")
        request = httpx_mock.get_request()
        assert request is not None
        assert "application_type" not in json.loads(request.content)

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            pytest.param("http://10.0.0.5:8080/callback", id="plain http on the network"),
            pytest.param("http://127.1:8080/callback", id="short form"),
            pytest.param("http://2130706433:8080/callback", id="decimal form"),
            pytest.param("http://0x7f000001:8080/callback", id="hex form"),
            pytest.param("http://foo.localhost:8080/callback", id="name under localhost"),
            pytest.param("com.example.app:/callback", id="private-use scheme"),
            pytest.param("ws://app.example.com/callback", id="another scheme"),
        ],
    )
    async def test_a_redirect_uri_a_configuration_would_refuse_is_refused_before_registering(
        self, httpx_mock: HTTPXMock, redirect_uri: str
    ) -> None:
        """A refusal after the server issued credentials would leave a registration standing."""
        with pytest.raises(ConfigurationError, match=r"loopback host \(redirect_uri\)") as exc_info:
            await register_client(_REGISTER_URL, redirect_uri)

        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert httpx_mock.get_requests() == []

    async def test_registration_url_with_userinfo_is_refused(self, httpx_mock: HTTPXMock) -> None:
        registration_url = "https://user:pw@auth.example.com/register"  # pragma: allowlist secret
        with pytest.raises(ConfigurationError, match=r"userinfo \(registration_url\)") as exc_info:
            await register_client(registration_url, _REDIRECT_URI)
        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert httpx_mock.get_requests() == []

    async def test_a_redirect_uri_the_client_cannot_read_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """A URL with no credential at all must not be reported as carrying one."""
        with pytest.raises(ConfigurationError, match=r"malformed URL \(redirect_uri\)") as exc_info:
            await register_client(_REGISTER_URL, "https://[::1/cb")

        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert httpx_mock.get_requests() == []

    async def test_redirect_uri_with_userinfo_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """The redirect URI is registered at the server, so a credential in it would be stored there."""
        redirect_uri = "https://user:pw@app.example.com/cb"  # pragma: allowlist secret

        with pytest.raises(ConfigurationError, match=r"userinfo \(redirect_uri\)") as exc_info:
            await register_client(_REGISTER_URL, redirect_uri)

        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert httpx_mock.get_requests() == []

    async def test_explicit_application_type_overrides_loopback_inference(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "x"})
        await register_client(_REGISTER_URL, "http://127.0.0.1:8080/callback", application_type=ApplicationType.WEB)
        request = httpx_mock.get_request()
        assert request is not None
        assert json.loads(request.content)["application_type"] == "web"

    @pytest.mark.parametrize(
        ("redirect_uri", "application_type", "expected"),
        [
            pytest.param("http://127.0.0.1:8080/callback", None, "none", id="inferred-native"),
            pytest.param(_REDIRECT_URI, None, "client_secret_post", id="inferred-nothing"),
            pytest.param(_REDIRECT_URI, ApplicationType.WEB, "client_secret_post", id="explicit-web"),
            pytest.param(_REDIRECT_URI, ApplicationType.NATIVE, "none", id="explicit-native"),
            pytest.param("http://127.0.0.1:8080/callback", ApplicationType.WEB, "client_secret_post", id="web-wins"),
        ],
    )
    async def test_the_requested_auth_method_follows_the_application_type(
        self, httpx_mock: HTTPXMock, redirect_uri: str, application_type: ApplicationType | None, expected: str
    ) -> None:
        """A native client cannot keep a secret, so it asks to be registered as a public client."""
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "x"})
        await register_client(_REGISTER_URL, redirect_uri, application_type=application_type)
        request = httpx_mock.get_request()
        assert request is not None
        assert json.loads(request.content)["token_endpoint_auth_method"] == expected

    @pytest.mark.parametrize(
        "method",
        [
            pytest.param("private_key_jwt", id="a method this library cannot perform"),
            pytest.param("", id="a name no method carries"),
            pytest.param("CLIENT_SECRET_POST", id="a member name rather than its wire name"),
        ],
    )
    async def test_an_auth_method_this_library_cannot_perform_is_refused_before_any_request(
        self, httpx_mock: HTTPXMock, method: str
    ) -> None:
        """The argument is the caller's own, so it is refused rather than asked for and then discarded."""
        with pytest.raises(ConfigurationError, match="cannot perform") as exc_info:
            await register_client(_REGISTER_URL, _REDIRECT_URI, token_endpoint_auth_method=method)  # ty: ignore
        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert httpx_mock.get_requests() == []

    @pytest.mark.parametrize(
        "method",
        [
            TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            TokenEndpointAuthMethod.CLIENT_SECRET_POST,
            TokenEndpointAuthMethod.NONE,
        ],
    )
    async def test_an_explicit_auth_method_wins_over_the_application_type(
        self, httpx_mock: HTTPXMock, method: TokenEndpointAuthMethod
    ) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "x"})
        await register_client(_REGISTER_URL, "http://127.0.0.1:8080/callback", token_endpoint_auth_method=method)
        request = httpx_mock.get_request()
        assert request is not None
        assert json.loads(request.content)["token_endpoint_auth_method"] == method


class TestCimdClientId:
    def test_valid_url_returned_unchanged(self) -> None:
        url = "https://app.example.com/oauth/client-metadata.json"
        assert cimd_client_id(url) == url

    def test_valid_url_with_nested_path(self) -> None:
        url = "https://app.example.com/a/b/client.json"
        assert cimd_client_id(url) == url

    def test_http_scheme_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="https"):
            cimd_client_id("http://app.example.com/client.json")

    def test_missing_path_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="path"):
            cimd_client_id("https://app.example.com")

    def test_bare_slash_path_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="path"):
            cimd_client_id("https://app.example.com/")

    def test_no_host_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="host"):
            cimd_client_id("https:///client.json")

    def test_valid_url_with_port_accepted(self) -> None:
        url = "https://app.example.com:8443/client.json"
        assert cimd_client_id(url) == url

    def test_invalid_port_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="valid URL"):
            cimd_client_id("https://app.example.com:notaport/client.json")

    def test_userinfo_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="username or password"):
            cimd_client_id("https://user:pass@app.example.com/client.json")  # pragma: allowlist secret

    def test_fragment_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="fragment"):
            cimd_client_id("https://app.example.com/client.json#section")

    def test_empty_fragment_delimiter_rejected(self) -> None:
        """A bare delimiter still carries a fragment, as the rule for a declared issuer also reads it."""
        with pytest.raises(ConfigurationError, match="fragment"):
            cimd_client_id("https://app.example.com/client.json#")

    def test_an_encoded_number_sign_in_the_path_is_accepted(self) -> None:
        """An encoded number sign is part of the document's path, not a delimiter."""
        url = "https://app.example.com/client%23one.json"
        assert cimd_client_id(url) == url

    def test_dot_path_segment_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="path segment"):
            cimd_client_id("https://app.example.com/./client.json")

    def test_dotdot_path_segment_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="path segment"):
            cimd_client_id("https://app.example.com/../client.json")

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("https://app.example.com/%2e/client.json", id="encoded dot"),
            pytest.param("https://app.example.com/%2E/client.json", id="encoded dot in upper case"),
            pytest.param("https://app.example.com/%2e%2e/client.json", id="encoded dot dot"),
            pytest.param("https://app.example.com/%2E%2E/client.json", id="encoded dot dot in upper case"),
            pytest.param("https://app.example.com/.%2e/client.json", id="one dot encoded"),
            pytest.param("https://app.example.com/%2e./client.json", id="the other dot encoded"),
        ],
    )
    def test_an_encoded_dot_path_segment_is_rejected(self, url: str) -> None:
        """RFC 3986 section 6.2.2 decodes an encoded dot before dot segments are removed, so it is one."""
        with pytest.raises(ConfigurationError, match="path segment"):
            cimd_client_id(url)

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("https://app.example.com/.well-known/client.json", id="a name starting with a dot"),
            pytest.param("https://app.example.com/a.b/client.json", id="a name holding a dot"),
            pytest.param("https://app.example.com/%2e%2ewell-known/client.json", id="an encoded dot in a name"),
            pytest.param("https://app.example.com/.../client.json", id="three dots"),
        ],
    )
    def test_a_path_segment_that_only_holds_dots_is_accepted(self, url: str) -> None:
        """Only a segment that is exactly one or two dots is a dot segment, however it is written."""
        assert cimd_client_id(url) == url

    def test_non_public_host_accepted(self) -> None:
        """The SSRF host block must NOT apply: the caller hosts this URL and the library never fetches it.

        Uses a loopback IP literal, which ``_is_blocked_host`` (applied by discovery
        and registration) rejects — so accepting it here proves the block is
        deliberately absent, and guards against a regression that adds it.
        """
        url = "https://127.0.0.1/client.json"
        assert cimd_client_id(url) == url

    def test_rejection_is_a_configuration_fault(self) -> None:
        """The client identifier is the caller's own argument, as the server and registration URLs are."""
        with pytest.raises(ConfigurationError) as exc_info:
            cimd_client_id("http://app.example.com/client.json")
        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert exc_info.value.retryable is False


class TestEndToEndFlow:
    async def test_discover_register_configure_exchange(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "oauth-protected-resource" in url:
                return httpx.Response(200, json=_prm_payload())
            if "oauth-authorization-server" in url:
                return httpx.Response(
                    200,
                    json={
                        "issuer": "https://auth.example.com",
                        "authorization_endpoint": "https://auth.example.com/authorize",
                        "token_endpoint": "https://auth.example.com/token",
                        "registration_endpoint": _REGISTER_URL,
                        "code_challenge_methods_supported": ["S256"],
                    },
                )
            if url == _REGISTER_URL:
                return httpx.Response(
                    201,
                    json={
                        "client_id": "dcr-client",
                        "client_secret": "dcr-secret",  # pragma: allowlist secret
                        "token_endpoint_auth_method": "client_secret_post",
                    },
                )
            if url == "https://auth.example.com/token":
                return httpx.Response(200, json={"access_token": "final-token", "token_type": "Bearer"})
            return httpx.Response(404)

        def transport_factory(url: str) -> httpx.MockTransport:
            seen.append(url)
            return httpx.MockTransport(handler)

        meta = await discover("https://mcp.example.com", transport_factory=transport_factory)
        registration_url = meta.registration_url
        assert registration_url is not None

        reg = await register_client(registration_url, _REDIRECT_URI, transport_factory=transport_factory)
        assert reg.client_id == "dcr-client"

        config = to_provider_config(meta, reg, redirect_uri=_REDIRECT_URI)
        assert config.token_url == "https://auth.example.com/token"
        assert config.use_pkce is True

        client = OAuthClient(config, transport_factory=transport_factory)
        authorize_url, pending = await client.get_authorization_url()
        assert authorize_url.startswith("https://auth.example.com/authorize")

        tokens = await client.exchange_code(
            AuthorizationCallback(code=SecretToken("auth-code"), state=pending.state), pending_state=pending
        )
        assert tokens.access_token.get_secret_value() == "final-token"

        # Every outbound connection was made through the injected transport factory.
        assert registration_url in seen
        assert "https://auth.example.com/token" in seen

    async def test_dcr_basic_registration_drives_config(self, httpx_mock: HTTPXMock) -> None:
        """A client the server registers as basic-only is configured as basic.

        The advertised set would derive client_secret_post; honoring the
        per-client registration is what keeps token exchange from sending the
        secret the wrong way.
        """
        httpx_mock.add_response(
            url=_REGISTER_URL,
            status_code=201,
            json={
                "client_id": "dcr-client",
                "client_secret": "dcr-secret",  # pragma: allowlist secret
                "token_endpoint_auth_method": "client_secret_basic",
            },
        )
        meta = ServerMetadata(
            authorize_url="https://auth.example.com/authorize",
            token_url="https://auth.example.com/token",
            token_endpoint_auth_methods=["client_secret_post"],
        )
        reg = await register_client(_REGISTER_URL, _REDIRECT_URI)
        config = to_provider_config(meta, reg)
        assert config.token_endpoint_auth_method == "client_secret_basic"


class TestTheRequestLimitsBoundMcpRequests:
    async def test_a_metadata_fetch_that_never_lands_is_refused_as_a_timeout(self) -> None:
        with pytest.raises(McpDiscoveryError) as refusal:
            await discover(
                "https://mcp.example.com",
                transport_factory=_crawling_transport,
                limits=RequestLimits(connect_seconds=0.05, request_seconds=0.05),
            )

        assert refusal.value.kind is FailureKind.TIMEOUT

    async def test_a_registration_that_never_lands_is_refused_as_a_timeout(self) -> None:
        with pytest.raises(McpRegistrationError) as refusal:
            await register_client(
                "https://as.example.com/register",
                "https://app.example.com/callback",
                transport_factory=_crawling_transport,
                limits=RequestLimits(connect_seconds=0.05, request_seconds=0.05),
            )

        assert refusal.value.kind is FailureKind.TIMEOUT
