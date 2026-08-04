from __future__ import annotations

import json
import logging
import traceback

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.client import OAuthClient
from apron_auth.errors import McpDiscoveryError, McpRegistrationError
from apron_auth.mcp import (
    _asm_candidate_urls,
    _honor_registered_auth_method,
    _is_blocked_host,
    _prm_candidate_urls,
    _select_auth_method,
    _str_list,
    _validate_url,
    cimd_client_id,
    discover,
    register_client,
    to_provider_config,
)
from apron_auth.models import ApplicationType, ProviderConfig, ServerMetadata, TokenEndpointAuthMethod

_REGISTER_URL = "https://auth.example.com/register"
_REDIRECT_URI = "https://app.example.com/callback"

_PRM_ROOT = "https://mcp.example.com/.well-known/oauth-protected-resource"
_PRM_PATH = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
_ASM_ROOT = "https://auth.example.com/.well-known/oauth-authorization-server"
_ASM_OIDC = "https://auth.example.com/.well-known/openid-configuration"


def _asm_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "scopes_supported": ["read", "write"],
    }
    payload.update(overrides)
    return payload


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
        config = to_provider_config(self._meta(), client_id="c", client_secret="s")
        assert isinstance(config, ProviderConfig)

    def test_maps_endpoints(self) -> None:
        meta = self._meta(revocation_url="https://auth.example.com/revoke")
        config = to_provider_config(meta, client_id="c", client_secret=SecretStr("s"))
        assert config.authorize_url == "https://auth.example.com/authorize"
        assert config.token_url == "https://auth.example.com/token"
        assert config.revocation_url == "https://auth.example.com/revoke"

    def test_confidential_client_uses_secret_post(self) -> None:
        config = to_provider_config(self._meta(), client_id="c", client_secret=SecretStr("s"))
        assert config.token_endpoint_auth_method == "client_secret_post"
        assert config.client_secret is not None

    def test_public_client_uses_none(self) -> None:
        config = to_provider_config(self._meta(), client_id="c")
        assert config.token_endpoint_auth_method == "none"
        assert config.client_secret is None

    def test_confidential_client_uses_basic_when_only_basic_advertised(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=["client_secret_basic"])
        config = to_provider_config(meta, client_id="c", client_secret="s")
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_confidential_client_defaults_basic_when_unadvertised(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=[])
        config = to_provider_config(meta, client_id="c", client_secret="s")
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_raises_when_server_requires_unsupported_auth_method(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=["private_key_jwt"])
        with pytest.raises(McpDiscoveryError):
            to_provider_config(meta, client_id="c", client_secret="s")

    def test_public_client_rejected_when_none_not_advertised(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=["client_secret_basic"])
        with pytest.raises(McpDiscoveryError):
            to_provider_config(meta, client_id="c")

    def test_registered_method_overrides_advertised_derivation(self) -> None:
        # The server advertises only client_secret_post, but this client was
        # registered as client_secret_basic; the per-client registration wins.
        config = to_provider_config(
            self._meta(token_endpoint_auth_methods=["client_secret_post"]),
            client_id="c",
            client_secret="s",
            registered_auth_method="client_secret_basic",
        )
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_registered_none_yields_public_client(self) -> None:
        config = to_provider_config(
            self._meta(),
            client_id="c",
            registered_auth_method="none",
        )
        assert config.token_endpoint_auth_method == "none"
        assert config.client_secret is None

    def test_registered_unsupported_method_raises(self) -> None:
        with pytest.raises(McpDiscoveryError):
            to_provider_config(
                self._meta(),
                client_id="c",
                client_secret="s",
                registered_auth_method="private_key_jwt",
            )

    def test_registered_confidential_method_without_secret_raises(self) -> None:
        with pytest.raises(McpDiscoveryError):
            to_provider_config(
                self._meta(),
                client_id="c",
                registered_auth_method="client_secret_basic",
            )

    def test_registered_none_with_secret_raises(self) -> None:
        # A public-client registration paired with a secret is contradictory;
        # emitting it would attach the secret to public-client requests.
        with pytest.raises(McpDiscoveryError):
            to_provider_config(
                self._meta(),
                client_id="c",
                client_secret="s",
                registered_auth_method="none",
            )

    def test_registered_empty_string_raises(self) -> None:
        with pytest.raises(McpDiscoveryError):
            to_provider_config(
                self._meta(),
                client_id="c",
                client_secret="s",
                registered_auth_method="",
            )

    def test_absent_registered_method_falls_back_to_derivation(self) -> None:
        meta = self._meta(token_endpoint_auth_methods=["client_secret_basic"])
        config = to_provider_config(meta, client_id="c", client_secret="s")
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_accepts_plain_string_secret(self) -> None:
        config = to_provider_config(self._meta(), client_id="c", client_secret="raw-secret")
        assert config.client_secret is not None
        assert config.client_secret.get_secret_value() == "raw-secret"

    def test_pkce_enabled_when_s256_supported(self) -> None:
        config = to_provider_config(self._meta(code_challenge_methods=["S256"]), client_id="c", client_secret="s")
        assert config.use_pkce is True

    def test_pkce_enabled_by_default_when_unadvertised(self) -> None:
        config = to_provider_config(self._meta(code_challenge_methods=[]), client_id="c", client_secret="s")
        assert config.use_pkce is True

    def test_pkce_disabled_when_s256_absent(self) -> None:
        config = to_provider_config(self._meta(code_challenge_methods=["plain"]), client_id="c", client_secret="s")
        assert config.use_pkce is False

    def test_scopes_and_redirect_passed(self) -> None:
        config = to_provider_config(
            self._meta(),
            client_id="c",
            client_secret="s",
            scopes=["a", "b"],
            redirect_uri="https://app.example.com/cb",
        )
        assert config.scopes == ["a", "b"]
        assert config.redirect_uri == "https://app.example.com/cb"

    def test_issuer_and_iss_requirement_threaded_from_metadata(self) -> None:
        meta = self._meta(issuer="https://auth.example.com", iss_parameter_supported=True)
        config = to_provider_config(meta, client_id="c", client_secret="s")
        assert config.issuer == "https://auth.example.com"
        assert config.require_iss is True

    def test_issuer_absent_leaves_config_unbound(self) -> None:
        config = to_provider_config(self._meta(), client_id="c", client_secret="s")
        assert config.issuer is None
        assert config.require_iss is False

    def test_resource_threaded_from_metadata(self) -> None:
        meta = self._meta(resource="https://mcp.example.com/mcp")
        config = to_provider_config(meta, client_id="c", client_secret="s")
        assert config.resource == "https://mcp.example.com/mcp"

    def test_resource_absent_leaves_config_unbound(self) -> None:
        config = to_provider_config(self._meta(), client_id="c", client_secret="s")
        assert config.resource is None

    def test_explicit_resource_overrides_metadata(self) -> None:
        meta = self._meta(resource="https://mcp.example.com")
        config = to_provider_config(
            meta,
            client_id="c",
            client_secret="s",
            resource="https://mcp.example.com/server/mcp",
        )
        assert config.resource == "https://mcp.example.com/server/mcp"

    def test_cimd_url_client_id_yields_public_config(self) -> None:
        url = cimd_client_id("https://app.example.com/oauth/client-metadata.json")
        config = to_provider_config(self._meta(), client_id=url, client_secret=None)
        assert config.client_id == "https://app.example.com/oauth/client-metadata.json"
        assert config.client_secret is None
        assert config.token_endpoint_auth_method == TokenEndpointAuthMethod.NONE

    def test_cimd_public_client_without_none_method_fails_fast(self) -> None:
        """A CIMD server offering only private_key_jwt (no 'none') must not yield a public config."""
        meta = self._meta(token_endpoint_auth_methods=["private_key_jwt"])
        with pytest.raises(McpDiscoveryError):
            to_provider_config(meta, client_id="https://app.example.com/c.json", client_secret=None)


class TestSelectAuthMethod:
    @pytest.mark.parametrize(
        ("secret", "advertised", "expected"),
        [
            # A public client (no secret) is "none" when the server advertises
            # nothing or explicitly lists "none".
            (None, [], TokenEndpointAuthMethod.NONE),
            (None, ["none", "client_secret_post"], TokenEndpointAuthMethod.NONE),
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

    @pytest.mark.parametrize(
        "advertised",
        [
            ["private_key_jwt"],
            ["tls_client_auth", "private_key_jwt"],
            ["none"],  # a confidential client whose server accepts only public clients
        ],
    )
    def test_raises_when_confidential_methods_unavailable(self, advertised: list[str]) -> None:
        with pytest.raises(McpDiscoveryError):
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
        with pytest.raises(McpDiscoveryError):
            _select_auth_method(None, advertised)

    def test_registered_method_wins_over_advertised(self) -> None:
        # The advertised set would derive post; the registered method wins.
        method = _select_auth_method(SecretStr("s"), ["client_secret_post"], registered="client_secret_basic")
        assert method == TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

    def test_empty_registered_string_is_validated_not_ignored(self) -> None:
        # An empty string is "provided" and rejected, not silently derived from
        # the advertised set — a malformed registration must not be masked.
        with pytest.raises(McpDiscoveryError):
            _select_auth_method(SecretStr("s"), ["client_secret_post"], registered="")


class TestHonorRegisteredAuthMethod:
    @pytest.mark.parametrize(
        ("registered", "secret", "expected"),
        [
            ("none", None, TokenEndpointAuthMethod.NONE),
            ("client_secret_post", SecretStr("s"), TokenEndpointAuthMethod.CLIENT_SECRET_POST),
            ("client_secret_basic", SecretStr("s"), TokenEndpointAuthMethod.CLIENT_SECRET_BASIC),
        ],
    )
    def test_returns_performable_method(self, registered: str, secret: SecretStr | None, expected: str) -> None:
        assert _honor_registered_auth_method(registered, secret) == expected

    @pytest.mark.parametrize(
        ("registered", "secret"),
        [
            # A method this library cannot perform, regardless of secret state.
            ("private_key_jwt", SecretStr("s")),
            ("tls_client_auth", None),
            # A confidential method with no secret to send it.
            ("client_secret_post", None),
            ("client_secret_basic", None),
            # A public client (none) must not carry a secret.
            ("none", SecretStr("s")),
            # An empty/invalid method string is validated, not ignored.
            ("", SecretStr("s")),
            ("", None),
        ],
    )
    def test_raises_when_unperformable(self, registered: str, secret: SecretStr | None) -> None:
        with pytest.raises(McpDiscoveryError):
            _honor_registered_auth_method(registered, secret)


class TestDiscover:
    async def test_happy_path_root_wellknown(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.authorize_url == "https://auth.example.com/authorize"
        assert meta.token_url == "https://auth.example.com/token"
        assert meta.code_challenge_methods == ["S256"]
        assert meta.scopes_supported == ["read", "write"]

    async def test_path_scoped_prm_preferred(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_PATH, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com/mcp")
        assert meta.token_url == "https://auth.example.com/token"

    async def test_prm_falls_back_to_root_after_404(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_PATH, status_code=404)
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com/mcp")
        assert meta.authorize_url == "https://auth.example.com/authorize"

    async def test_resource_metadata_hint_tried_first(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://mcp.example.com/custom-prm",
            json={"authorization_servers": ["https://auth.example.com"]},
        )
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover(
            "https://mcp.example.com",
            resource_metadata_url="https://mcp.example.com/custom-prm",
        )
        assert meta.token_url == "https://auth.example.com/token"

    async def test_asm_oidc_fallback(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, status_code=404)
        httpx_mock.add_response(url=_ASM_OIDC, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.authorize_url == "https://auth.example.com/authorize"

    async def test_registration_and_revocation_surfaced(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
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
            json={"authorization_servers": ["", "https://auth.example.com"]},
        )
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.token_url == "https://auth.example.com/token"

    async def test_skipped_candidate_logged_at_debug(self, httpx_mock: HTTPXMock, caplog) -> None:
        """A skipped discovery candidate is logged at debug with a non-sensitive reason."""
        httpx_mock.add_response(url=_PRM_PATH, status_code=404)
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        with caplog.at_level(logging.DEBUG, logger="apron_auth.mcp"):
            await discover("https://mcp.example.com/mcp")
        assert any("protected resource metadata returned HTTP 404" in message for message in caplog.messages)

    async def test_issuer_and_iss_support_captured(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
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

    async def test_issuer_and_iss_support_default_when_absent(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.issuer is None
        assert meta.iss_parameter_supported is False

    async def test_supports_cimd_captured(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(
            url=_ASM_ROOT,
            json=_asm_payload(client_id_metadata_document_supported=True),
        )
        meta = await discover("https://mcp.example.com")
        assert meta.supports_cimd is True

    async def test_supports_cimd_defaults_false_when_absent(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.supports_cimd is False

    async def test_supports_cimd_false_when_not_true(self, httpx_mock: HTTPXMock) -> None:
        """A non-boolean flag value must not be read as support."""
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload(client_id_metadata_document_supported="yes"))
        meta = await discover("https://mcp.example.com")
        assert meta.supports_cimd is False

    async def test_resource_identifier_captured(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=_PRM_ROOT,
            json={
                "resource": "https://mcp.example.com",
                "authorization_servers": ["https://auth.example.com"],
            },
        )
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.resource == "https://mcp.example.com"

    async def test_resource_none_when_prm_omits_it(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.resource is None

    async def test_resource_ignored_when_not_a_string(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=_PRM_ROOT,
            json={"resource": 123, "authorization_servers": ["https://auth.example.com"]},
        )
        httpx_mock.add_response(url=_ASM_ROOT, json=_asm_payload())
        meta = await discover("https://mcp.example.com")
        assert meta.resource is None

    async def test_missing_token_endpoint_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://auth.example.com"]})
        httpx_mock.add_response(url=_ASM_ROOT, json={"authorization_endpoint": "https://auth.example.com/authorize"})
        with pytest.raises(McpDiscoveryError):
            await discover("https://mcp.example.com")

    async def test_unfetchable_prm_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, status_code=500)
        with pytest.raises(McpDiscoveryError):
            await discover("https://mcp.example.com")

    async def test_non_https_server_url_rejected(self) -> None:
        with pytest.raises(McpDiscoveryError):
            await discover("http://mcp.example.com")

    async def test_non_https_authorization_server_rejected(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["http://auth.internal"]})
        with pytest.raises(McpDiscoveryError):
            await discover("https://mcp.example.com")

    async def test_loopback_server_rejected(self) -> None:
        with pytest.raises(McpDiscoveryError):
            await discover("https://127.0.0.1")

    async def test_localhost_server_rejected(self) -> None:
        with pytest.raises(McpDiscoveryError):
            await discover("https://localhost")

    async def test_link_local_metadata_ip_rejected(self) -> None:
        with pytest.raises(McpDiscoveryError):
            await discover("https://169.254.169.254")

    async def test_private_ip_authorization_server_rejected(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_PRM_ROOT, json={"authorization_servers": ["https://10.0.0.5"]})
        with pytest.raises(McpDiscoveryError):
            await discover("https://mcp.example.com")

    async def test_url_validator_invoked_and_rejection_wrapped(self) -> None:
        seen: list[str] = []

        def validator(url: str) -> None:
            seen.append(url)
            msg = "blocked by policy"
            raise ValueError(msg)

        with pytest.raises(McpDiscoveryError):
            await discover("https://mcp.example.com", url_validator=validator)
        assert seen == ["https://mcp.example.com"]

    async def test_transport_factory_used_for_requests(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth-protected-resource" in request.url.path:
                return httpx.Response(200, json={"authorization_servers": ["https://auth.example.com"]})
            return httpx.Response(200, json=_asm_payload())

        def factory(url: str) -> httpx.MockTransport:
            calls.append(url)
            return httpx.MockTransport(handler)

        meta = await discover("https://mcp.example.com", transport_factory=factory)
        assert meta.token_url == "https://auth.example.com/token"
        assert calls


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
            ("mcp.example.com", False),
            ("8.8.8.8", False),
            ("134744072", False),
            ("2606:4700:4700::1111", False),
        ],
    )
    def test_classifies_host(self, host: str, blocked: bool) -> None:
        assert _is_blocked_host(host) is blocked


class TestStrList:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (["a", "b"], ["a", "b"]),
            (["a", 1, None, "b"], ["a", "b"]),
            ([], []),
            (None, []),
            ("not-a-list", []),
            ({"a": 1}, []),
        ],
    )
    def test_filters_to_strings(self, value: object, expected: list[str]) -> None:
        assert _str_list(value) == expected


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
        ],
    )
    def test_candidate_order(self, hint: str | None, server_url: str, expected: list[str]) -> None:
        assert _prm_candidate_urls(hint, server_url) == expected


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
        ],
    )
    def test_candidate_order(self, auth_server: str, expected: list[str]) -> None:
        assert _asm_candidate_urls(auth_server) == expected


class TestValidateUrl:
    def test_https_public_host_passes(self) -> None:
        _validate_url("https://mcp.example.com/x", None)

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
        ],
    )
    def test_rejects_unusable_url(self, url: str) -> None:
        with pytest.raises(McpDiscoveryError):
            _validate_url(url, None)

    def test_rejects_malformed_url(self) -> None:
        with pytest.raises(McpDiscoveryError):
            _validate_url("https://[::1", None)

    def test_invokes_validator_when_url_is_acceptable(self) -> None:
        seen: list[str] = []
        _validate_url("https://mcp.example.com", seen.append)
        assert seen == ["https://mcp.example.com"]

    def test_wraps_validator_rejection(self) -> None:
        def validator(url: str) -> None:
            del url
            msg = "blocked by policy"
            raise ValueError(msg)

        with pytest.raises(McpDiscoveryError, match="blocked by policy"):
            _validate_url("https://mcp.example.com", validator)

    def test_passes_through_validator_discovery_error(self) -> None:
        def validator(url: str) -> None:
            del url
            msg = "direct"
            raise McpDiscoveryError(msg)

        with pytest.raises(McpDiscoveryError, match="direct") as exc_info:
            _validate_url("https://mcp.example.com", validator)
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

    async def test_missing_client_id_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_secret": "s"})
        with pytest.raises(McpRegistrationError):
            await register_client(_REGISTER_URL, _REDIRECT_URI)

    async def test_registration_error_never_leaks_client_secret(self, httpx_mock: HTTPXMock) -> None:
        """A registration failure must not surface the issued secret anywhere.

        A malformed success body can still carry ``client_secret`` while lacking
        ``client_id``; neither the error's message nor its rendered traceback
        (which walks the ``__cause__``/``__context__`` chain) may expose it.
        """
        leaked = "top-secret-value"  # pragma: allowlist secret
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_secret": leaked})
        with pytest.raises(McpRegistrationError) as exc_info:
            await register_client(_REGISTER_URL, _REDIRECT_URI)
        rendered = "".join(
            traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
        )
        assert leaked not in str(exc_info.value)
        assert leaked not in rendered

    @pytest.mark.parametrize("status", [400, 401, 403, 500])
    async def test_non_success_status_raises(self, httpx_mock: HTTPXMock, status: int) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=status, json={"error": "invalid_client_metadata"})
        with pytest.raises(McpRegistrationError):
            await register_client(_REGISTER_URL, _REDIRECT_URI)

    async def test_non_object_response_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json=["not", "a", "dict"])
        with pytest.raises(McpRegistrationError):
            await register_client(_REGISTER_URL, _REDIRECT_URI)

    @pytest.mark.parametrize("url", ["http://auth.example.com/register", "https://127.0.0.1/register"])
    async def test_unsafe_registration_url_rejected(self, url: str) -> None:
        with pytest.raises(McpRegistrationError):
            await register_client(url, _REDIRECT_URI)

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

    @pytest.mark.parametrize("application_type", [ApplicationType.WEB, ApplicationType.NATIVE])
    async def test_explicit_application_type_included_in_payload(
        self, httpx_mock: HTTPXMock, application_type: str
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
            "http://127.1:8080/callback",
            "http://2130706433:8080/callback",
            "http://0x7f000001:8080/callback",
            "http://0177.0.0.1:8080/callback",
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

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            "https://app.example.com/callback",
            "http://10.0.0.5:8080/callback",
        ],
    )
    async def test_application_type_omitted_for_non_loopback_redirect(
        self, httpx_mock: HTTPXMock, redirect_uri: str
    ) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "x"})
        await register_client(_REGISTER_URL, redirect_uri)
        request = httpx_mock.get_request()
        assert request is not None
        assert "application_type" not in json.loads(request.content)

    async def test_explicit_application_type_overrides_loopback_inference(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_id": "x"})
        await register_client(_REGISTER_URL, "http://127.0.0.1:8080/callback", application_type=ApplicationType.WEB)
        request = httpx_mock.get_request()
        assert request is not None
        assert json.loads(request.content)["application_type"] == "web"

    async def test_invalid_application_type_rejected_locally(self) -> None:
        with pytest.raises(ValueError, match="application_type"):
            await register_client(_REGISTER_URL, _REDIRECT_URI, application_type="desktop")


class TestCimdClientId:
    def test_valid_url_returned_unchanged(self) -> None:
        url = "https://app.example.com/oauth/client-metadata.json"
        assert cimd_client_id(url) == url

    def test_valid_url_with_nested_path(self) -> None:
        url = "https://app.example.com/a/b/client.json"
        assert cimd_client_id(url) == url

    def test_http_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="https"):
            cimd_client_id("http://app.example.com/client.json")

    def test_missing_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="path"):
            cimd_client_id("https://app.example.com")

    def test_bare_slash_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="path"):
            cimd_client_id("https://app.example.com/")

    def test_no_host_rejected(self) -> None:
        with pytest.raises(ValueError, match="host"):
            cimd_client_id("https:///client.json")

    def test_valid_url_with_port_accepted(self) -> None:
        url = "https://app.example.com:8443/client.json"
        assert cimd_client_id(url) == url

    def test_invalid_port_rejected(self) -> None:
        with pytest.raises(ValueError, match="valid URL"):
            cimd_client_id("https://app.example.com:notaport/client.json")

    def test_userinfo_rejected(self) -> None:
        with pytest.raises(ValueError, match="username or password"):
            cimd_client_id("https://user:pass@app.example.com/client.json")  # pragma: allowlist secret

    def test_fragment_rejected(self) -> None:
        with pytest.raises(ValueError, match="fragment"):
            cimd_client_id("https://app.example.com/client.json#section")

    def test_dot_path_segment_rejected(self) -> None:
        with pytest.raises(ValueError, match="path segment"):
            cimd_client_id("https://app.example.com/./client.json")

    def test_dotdot_path_segment_rejected(self) -> None:
        with pytest.raises(ValueError, match="path segment"):
            cimd_client_id("https://app.example.com/../client.json")

    def test_non_public_host_accepted(self) -> None:
        """The SSRF host block must NOT apply: the caller hosts this URL and the library never fetches it.

        Uses a loopback IP literal, which ``_is_blocked_host`` (applied by discovery
        and registration) rejects — so accepting it here proves the block is
        deliberately absent, and guards against a regression that adds it.
        """
        url = "https://127.0.0.1/client.json"
        assert cimd_client_id(url) == url


class TestEndToEndFlow:
    async def test_discover_register_configure_exchange(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "oauth-protected-resource" in url:
                return httpx.Response(200, json={"authorization_servers": ["https://auth.example.com"]})
            if "oauth-authorization-server" in url:
                return httpx.Response(
                    200,
                    json={
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

        config = to_provider_config(
            meta,
            client_id=reg.client_id,
            client_secret=reg.client_secret,
            registered_auth_method=reg.token_endpoint_auth_method,
            redirect_uri=_REDIRECT_URI,
        )
        assert config.token_url == "https://auth.example.com/token"
        assert config.use_pkce is True

        client = OAuthClient(config, transport_factory=transport_factory)
        authorize_url, pending = await client.get_authorization_url()
        assert authorize_url.startswith("https://auth.example.com/authorize")

        tokens = await client.exchange_code(
            code="auth-code",
            redirect_uri=_REDIRECT_URI,
            code_verifier=pending.code_verifier,
        )
        assert tokens.access_token == "final-token"

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
        config = to_provider_config(
            meta,
            client_id=reg.client_id,
            client_secret=reg.client_secret,
            registered_auth_method=reg.token_endpoint_auth_method,
        )
        assert config.token_endpoint_auth_method == "client_secret_basic"
