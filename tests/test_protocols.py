from __future__ import annotations

from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from any_auth.models import OAuthPendingState, ProviderConfig
from any_auth.protocols import RevocationHandler, StandardRevocationHandler, StateStore


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

    async def test_failed_revocation(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=400)
        config = _make_config()
        handler = StandardRevocationHandler()
        result = await handler.revoke("bad-token", config)
        assert result is False
