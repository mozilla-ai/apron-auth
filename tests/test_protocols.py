from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.errors import RevocationError
from apron_auth.models import IdentityMaterial, IdentityProfile, OAuthPendingState, ProviderConfig
from apron_auth.protocols import IdentityResolver, RevocationHandler, StandardRevocationHandler, StateStore


def _make_config(**overrides: object) -> ProviderConfig:
    defaults = {
        "client_id": "test-client",
        "client_secret": SecretStr("test-secret"),
        "authorize_url": "https://provider.example.com/authorize",
        "token_url": "https://provider.example.com/token",
        "revocation_url": "https://provider.example.com/revoke",
    }
    defaults.update(overrides)
    return ProviderConfig(**defaults)


class TestStateStoreProtocol:
    def test_class_satisfies_protocol(self):
        class MemoryStore:
            async def save(self, state: OAuthPendingState) -> None:
                pass

            async def consume(self, state_key: str) -> OAuthPendingState | None:
                return None

        assert isinstance(MemoryStore(), StateStore)


class TestRevocationHandlerProtocol:
    def test_class_satisfies_protocol(self):
        class CustomHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                return True

        assert isinstance(CustomHandler(), RevocationHandler)


class TestIdentityResolverProtocol:
    def test_callable_satisfies_protocol(self):
        class DummyIdentityHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                return IdentityProfile(subject="sub")

        def resolver(config: ProviderConfig):
            del config
            return DummyIdentityHandler()

        assert isinstance(resolver, IdentityResolver)


class TestStandardRevocationHandler:
    async def test_successful_revocation(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=200)
        config = _make_config()
        handler = StandardRevocationHandler()
        result = await handler.revoke("access-token-abc", config)
        assert result is True
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert b"token=access-token-abc" in request.content

    @pytest.mark.parametrize(
        ("secret", "auth_method", "expect_basic_auth"),
        [
            (SecretStr("test-secret"), "client_secret_post", True),
            (None, "none", False),
        ],
    )
    async def test_revocation_basic_auth_only_when_secret_present(
        self, httpx_mock: HTTPXMock, secret, auth_method, expect_basic_auth
    ):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=200)
        config = _make_config(client_secret=secret, token_endpoint_auth_method=auth_method)
        handler = StandardRevocationHandler()
        result = await handler.revoke("access-token-abc", config)
        assert result is True
        request = httpx_mock.get_request()
        assert b"token=access-token-abc" in request.content
        assert ("authorization" in request.headers) is expect_basic_auth

    async def test_public_client_revocation_sends_client_id(self, httpx_mock: HTTPXMock):
        """RFC 7009 section 5: a public client identifies via client_id in the body."""
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=200)
        config = _make_config(client_secret=None, token_endpoint_auth_method="none")
        handler = StandardRevocationHandler()
        result = await handler.revoke("access-token-abc", config)
        assert result is True
        request = httpx_mock.get_request()
        assert b"client_id=test-client" in request.content
        assert "authorization" not in request.headers

    async def test_public_client_with_lingering_secret_sends_no_basic_auth(self, httpx_mock: HTTPXMock) -> None:
        """A public client must present no client authentication on revocation
        even if a secret lingers on the config.

        Validation forbids ``none`` + secret, so ``model_construct`` bypasses it
        to exercise the revocation path directly and prove the secret is not
        leaked as HTTP Basic credentials.
        """
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=200)
        config = ProviderConfig.model_construct(
            client_id="test-client",
            client_secret=SecretStr("leaked-secret"),
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
            revocation_url="https://provider.example.com/revoke",
            token_endpoint_auth_method="none",
        )
        handler = StandardRevocationHandler()
        result = await handler.revoke("access-token-abc", config)
        assert result is True
        request = httpx_mock.get_request()
        assert request is not None
        assert "authorization" not in request.headers
        assert b"client_id=test-client" in request.content

    async def test_public_client_revocation_suppresses_injected_default_auth(self):
        """A public client must not leak an injected client's default auth to the revocation URL."""
        seen: list[bool] = []

        def responder(request: httpx.Request) -> httpx.Response:
            seen.append("authorization" in request.headers)
            return httpx.Response(200)

        client = httpx.AsyncClient(
            auth=("default-user", "default-secret"),  # pragma: allowlist secret
            transport=httpx.MockTransport(responder),
        )
        config = _make_config(client_secret=None, token_endpoint_auth_method="none")
        handler = StandardRevocationHandler(client=client)
        result = await handler.revoke("access-token-abc", config)
        await client.aclose()
        assert result is True
        assert seen == [False]

    async def test_failed_revocation(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=400)
        config = _make_config()
        handler = StandardRevocationHandler()
        result = await handler.revoke("bad-token", config)
        assert result is False

    async def test_successful_revocation_with_injected_client(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=200)
        config = _make_config()
        client = httpx.AsyncClient()
        handler = StandardRevocationHandler(client=client)
        result = await handler.revoke("access-token-abc", config)
        assert result is True
        assert not client.is_closed
        await client.aclose()

    async def test_failed_revocation_with_injected_client(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=400)
        config = _make_config()
        client = httpx.AsyncClient()
        handler = StandardRevocationHandler(client=client)
        result = await handler.revoke("bad-token", config)
        assert result is False
        assert not client.is_closed
        await client.aclose()

    async def test_network_error_raises_revocation_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        config = _make_config()
        handler = StandardRevocationHandler()
        with pytest.raises(RevocationError, match="Connection refused") as exc_info:
            await handler.revoke("access-token-abc", config)
        assert isinstance(exc_info.value.__cause__, httpx.ConnectError)

    async def test_network_error_with_injected_client(self, httpx_mock: HTTPXMock):
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        config = _make_config()
        client = httpx.AsyncClient()
        handler = StandardRevocationHandler(client=client)
        with pytest.raises(RevocationError, match="Connection refused") as exc_info:
            await handler.revoke("access-token-abc", config)
        assert isinstance(exc_info.value.__cause__, httpx.ConnectError)
        assert not client.is_closed
        await client.aclose()

    async def test_transport_factory_used_for_revocation(self):
        """The revocation request routes through the caller's transport_factory.

        The revocation URL is server-supplied, so a caller pinning DNS for SSRF
        defense must see revocation honor the same seam as the token request.
        """
        calls: list[str] = []

        def responder(request: httpx.Request) -> httpx.Response:
            del request
            return httpx.Response(200)

        def factory(url: str) -> httpx.MockTransport:
            calls.append(url)
            return httpx.MockTransport(responder)

        config = _make_config()
        handler = StandardRevocationHandler(transport_factory=factory)
        result = await handler.revoke("access-token-abc", config)
        assert result is True
        assert calls == ["https://provider.example.com/revoke"]
