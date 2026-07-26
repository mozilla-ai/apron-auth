from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.errors import McpDiscoveryError, McpRegistrationError
from apron_auth.mcp import (
    _asm_candidate_urls,
    _is_blocked_host,
    _prm_candidate_urls,
    _str_list,
    _validate_url,
    discover,
    register_client,
    to_provider_config,
)
from apron_auth.models import ProviderConfig, ServerMetadata

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
            ("mcp.example.com", False),
            ("8.8.8.8", False),
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
        ],
    )
    def test_rejects_unusable_url(self, url: str) -> None:
        with pytest.raises(McpDiscoveryError):
            _validate_url(url, None)

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

    async def test_missing_client_id_raises(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=_REGISTER_URL, status_code=201, json={"client_secret": "s"})
        with pytest.raises(McpRegistrationError):
            await register_client(_REGISTER_URL, _REDIRECT_URI)

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
