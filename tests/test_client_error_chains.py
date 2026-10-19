"""Errors that OAuthClient raises carry no secret from the failed operation.

A failed token request's HTTP client error holds a request with the client secret and the grant.
A handler's error can hold a request with the access token or the token to revoke.
None of these may be reachable from the error the client raises.
"""

from __future__ import annotations

import time
import traceback
from collections.abc import Callable

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.client import OAuthClient, _redact, _TokenEndpointError
from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    OAuthError,
    RevocationError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import IdentityMaterial, IdentityProfile, OAuthPendingState, ProviderConfig, TokenSet

CLIENT_SECRET = "client-SECRET-xyz"  # pragma: allowlist secret
CODE = "code-SECRET-xyz"
VERIFIER = "verifier-SECRET-xyz"
REFRESH_TOKEN = "refresh-SECRET-xyz"  # pragma: allowlist secret
ACCESS_TOKEN = "access-SECRET-xyz"  # pragma: allowlist secret
RAW_TEXT = "raw transport text"
SECRETS = (CLIENT_SECRET, CODE, VERIFIER, REFRESH_TOKEN, ACCESS_TOKEN)


def _config(**overrides: object) -> ProviderConfig:
    defaults: dict[str, object] = {
        "client_id": "cid",
        "client_secret": SecretStr(CLIENT_SECRET),
        "authorize_url": "https://provider.example.com/authorize",
        "token_url": "https://provider.example.com/token",
        "revocation_url": "https://provider.example.com/revoke",
        "scopes": ["email"],
    }
    defaults.update(overrides)
    return ProviderConfig(**defaults)


def _pending_state(nonce: str | None = None) -> OAuthPendingState:
    return OAuthPendingState(
        state="pending-state",
        redirect_uri="https://app.example.com/callback",
        code_verifier=VERIFIER,
        nonce=nonce,
        created_at=time.time(),
    )


def _linked_errors(error: BaseException) -> list[BaseException]:
    """Return every exception reachable from ``error`` through causes and contexts."""
    found: list[BaseException] = []
    pending = [error]
    while pending:
        current = pending.pop()
        if current in found:
            continue
        found.append(current)
        pending.extend(link for link in (current.__cause__, current.__context__) if link is not None)
    return found


def _assert_carries_no_secret(error: OAuthError, *secrets: str) -> None:
    cause = error.__cause__
    assert error.__context__ is cause
    if cause is not None:
        assert isinstance(cause, _TokenEndpointError)
        assert cause.__cause__ is None
        assert cause.__context__ is None
    for linked in _linked_errors(error):
        try:
            request = getattr(linked, "request", None)
        except RuntimeError:
            # An httpx error whose request was never set raises on access.
            request = None
        assert request is None, f"{type(linked).__name__} holds a request"
    formatted = "".join(traceback.format_exception(error))
    for secret in secrets:
        assert secret not in formatted
    assert RAW_TEXT not in formatted


def _refuse(failure: type[httpx.RequestError]) -> Callable[[httpx.Request], httpx.Response]:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise failure(f"{RAW_TEXT} for url {request.url}", request=request)

    return refuse


TRANSPORT_FAILURES = [
    pytest.param(httpx.ConnectError, "network error", id="network"),
    pytest.param(httpx.ReadTimeout, "request timed out", id="timeout"),
    pytest.param(httpx.UnsupportedProtocol, "request failed", id="other"),
]


class TestTokenRequestErrors:
    async def _exchange_error(self) -> TokenExchangeError:
        client = OAuthClient(_config())
        with pytest.raises(TokenExchangeError) as exc_info:
            await client.exchange_code(code=CODE, state="pending-state", pending_state=_pending_state())
        return exc_info.value

    async def _refresh_error(self) -> TokenRefreshError:
        client = OAuthClient(_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(REFRESH_TOKEN)
        return exc_info.value

    @pytest.mark.parametrize(("failure", "kind"), TRANSPORT_FAILURES)
    async def test_exchange_transport_failure_carries_no_secret(
        self, failure: type[httpx.RequestError], kind: str, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_callback(_refuse(failure))

        error = await self._exchange_error()

        assert str(error) == kind
        _assert_carries_no_secret(error, CLIENT_SECRET, CODE, VERIFIER)

    @pytest.mark.parametrize(("failure", "kind"), TRANSPORT_FAILURES)
    async def test_refresh_transport_failure_carries_no_secret(
        self, failure: type[httpx.RequestError], kind: str, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_callback(_refuse(failure))

        error = await self._refresh_error()

        assert str(error) == kind
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_exchange_server_error_carries_no_secret(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=503, json={})

        error = await self._exchange_error()

        assert str(error) == "HTTP 503"
        _assert_carries_no_secret(error, CLIENT_SECRET, CODE, VERIFIER)

    async def test_refresh_server_error_carries_no_secret(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=503, json={})

        error = await self._refresh_error()

        assert str(error) == "HTTP 503"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_refresh_oauth_error_carries_no_secret(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=400, json={"error": "invalid_request"})

        error = await self._refresh_error()

        assert str(error) == "invalid_request"
        assert error.error_code == "invalid_request"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_refresh_unreadable_response_carries_no_decoder_text(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=200, content=f"not json {REFRESH_TOKEN}".encode())

        error = await self._refresh_error()

        assert str(error) == "token response could not be read"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_refresh_error_description_echo_is_redacted(self, httpx_mock: HTTPXMock) -> None:
        description = f"token {REFRESH_TOKEN} for secret {CLIENT_SECRET} is not valid"
        httpx_mock.add_response(status_code=400, json={"error": "invalid_request", "error_description": description})

        error = await self._refresh_error()

        assert str(error) == "invalid_request: token [redacted] for secret [redacted] is not valid"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_exchange_error_description_echo_is_redacted(self, httpx_mock: HTTPXMock) -> None:
        description = f"code {CODE} does not match verifier {VERIFIER}"
        httpx_mock.add_response(status_code=400, json={"error": "invalid_grant", "error_description": description})

        error = await self._exchange_error()

        assert str(error) == "invalid_grant: code [redacted] does not match verifier [redacted]"
        _assert_carries_no_secret(error, CLIENT_SECRET, CODE, VERIFIER)

    async def test_server_error_description_echo_is_redacted(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=503, json={"error_description": f"retry {REFRESH_TOKEN} later"})

        error = await self._refresh_error()

        assert str(error) == "HTTP 503: retry [redacted] later"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_error_code_echo_is_redacted(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=400, json={"error": REFRESH_TOKEN})

        error = await self._refresh_error()

        assert error.error_code == "[redacted]"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_form_encoded_echo_is_redacted(self, httpx_mock: HTTPXMock) -> None:
        secret = "s3cr/t+=x"  # pragma: allowlist secret
        httpx_mock.add_response(
            status_code=400, json={"error": "invalid_client", "error_description": "bad s3cr%2Ft%2B%3Dx"}
        )
        client = OAuthClient(_config(client_secret=SecretStr(secret)))

        with pytest.raises(OAuthError) as exc_info:
            await client.refresh_token(REFRESH_TOKEN)

        assert str(exc_info.value) == "invalid_client: bad [redacted]"

    async def test_redacted_error_code_still_classifies_the_failure(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=400, json={"error": "invalid_grant"})
        client = OAuthClient(_config())

        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token("grant")

        assert exc_info.value.error_code == "invalid_[redacted]"
        assert exc_info.value.kind is FailureKind.REJECTED
        assert "grant" not in str(exc_info.value).replace("invalid_[redacted]", "")


class TestHandlerErrors:
    @pytest.mark.parametrize(("failure", "kind"), TRANSPORT_FAILURES)
    async def test_revocation_handler_transport_failure_carries_no_secret(
        self, failure: type[httpx.RequestError], kind: str
    ) -> None:
        class FailingHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                request = httpx.Request("POST", f"https://provider.example.com/revoke?token={token}")
                raise failure(RAW_TEXT, request=request)

        client = OAuthClient(_config(), revocation_handler=FailingHandler())
        with pytest.raises(RevocationError) as exc_info:
            await client.revoke_token(ACCESS_TOKEN)

        assert str(exc_info.value) == f"Failed to revoke token: {kind}"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)

    async def test_revocation_handler_unexpected_error_carries_no_text(self) -> None:
        class BrokenHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                raise RuntimeError(f"{RAW_TEXT} {token}")

        client = OAuthClient(_config(), revocation_handler=BrokenHandler())
        with pytest.raises(RevocationError) as exc_info:
            await client.revoke_token(ACCESS_TOKEN)

        assert str(exc_info.value) == "Failed to revoke token"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)

    @pytest.mark.parametrize(("failure", "kind"), TRANSPORT_FAILURES)
    async def test_identity_handler_transport_failure_carries_no_secret(
        self, failure: type[httpx.RequestError], kind: str
    ) -> None:
        class FailingHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                request = httpx.Request(
                    "GET",
                    "https://provider.example.com/me",
                    headers={"Authorization": f"Bearer {material.access_token}"},
                )
                raise failure(RAW_TEXT, request=request)

        client = OAuthClient(_config(), identity_handler=FailingHandler())
        with pytest.raises(IdentityFetchError) as exc_info:
            await client.fetch_identity(TokenSet(access_token=ACCESS_TOKEN))

        assert str(exc_info.value) == f"Failed to fetch identity: {kind}"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)

    async def test_identity_handler_unexpected_error_carries_no_text(self) -> None:
        class BrokenHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                raise RuntimeError(f"{RAW_TEXT} {material.access_token}")

        client = OAuthClient(_config(), identity_handler=BrokenHandler())
        with pytest.raises(IdentityFetchError) as exc_info:
            await client.fetch_identity(TokenSet(access_token=ACCESS_TOKEN))

        assert str(exc_info.value) == "Failed to fetch identity"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)

    async def test_library_error_from_a_revocation_handler_keeps_its_message(self) -> None:
        class MisconfiguredHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                raise ConfigurationError("revocation needs client authentication")

        client = OAuthClient(_config(), revocation_handler=MisconfiguredHandler())
        with pytest.raises(RevocationError) as exc_info:
            await client.revoke_token(ACCESS_TOKEN)

        assert str(exc_info.value) == "revocation needs client authentication"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)

    async def test_library_error_from_an_identity_handler_keeps_its_message(self) -> None:
        class MisconfiguredHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                raise ConfigurationError("config names a different issuer")

        client = OAuthClient(_config(), identity_handler=MisconfiguredHandler())
        with pytest.raises(IdentityFetchError) as exc_info:
            await client.fetch_identity(TokenSet(access_token=ACCESS_TOKEN))

        assert str(exc_info.value) == "config names a different issuer"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)


class TestHandlerDomainErrors:
    async def test_revocation_handler_error_loses_its_chain(self) -> None:
        class ChainingHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                request = httpx.Request("POST", "https://provider.example.com/revoke", data={"token": token})
                try:
                    raise httpx.ConnectError(RAW_TEXT, request=request)
                except httpx.ConnectError as exc:
                    raise RevocationError("Custom revocation failed", kind=FailureKind.UNREACHABLE) from exc

        client = OAuthClient(_config(), revocation_handler=ChainingHandler())
        with pytest.raises(RevocationError) as exc_info:
            await client.revoke_token(ACCESS_TOKEN)

        assert str(exc_info.value) == "Custom revocation failed"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)

    async def test_identity_handler_error_loses_its_chain_and_keeps_its_type(self) -> None:
        class CustomIdentityError(IdentityFetchError):
            default_kind = FailureKind.UNREACHABLE

        class ChainingHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                request = httpx.Request(
                    "GET",
                    "https://provider.example.com/me",
                    headers={"Authorization": f"Bearer {material.access_token}"},
                )
                try:
                    raise httpx.ConnectError(RAW_TEXT, request=request)
                except httpx.ConnectError as exc:
                    raise CustomIdentityError("Custom identity failed") from exc

        client = OAuthClient(_config(), identity_handler=ChainingHandler())
        with pytest.raises(CustomIdentityError) as exc_info:
            await client.fetch_identity(TokenSet(access_token=ACCESS_TOKEN))

        assert str(exc_info.value) == "Custom identity failed"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)


class TestRedact:
    def test_a_short_value_inside_a_placeholder_leaves_the_placeholder_intact(self) -> None:
        assert _redact("x long-value-1 y red z", ["long-value-1", "red"]) == "x [redacted] y [redacted] z"
