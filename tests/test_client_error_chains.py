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

from apron_auth.client import OAuthClient
from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    OAuthError,
    RevocationError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import FreshTokenSet, IdentityMaterial, IdentityProfile, OAuthPendingState, ProviderConfig

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


def _frame_names(error: BaseException) -> list[str]:
    """Return the qualified function names on an error's own traceback, outermost first."""
    names = []
    tb = error.__traceback__
    while tb is not None:
        names.append(tb.tb_frame.f_code.co_qualname)
        tb = tb.tb_next
    return names


def _assert_carries_no_secret(error: OAuthError, *secrets: str) -> None:
    # No chain at all: the internal token-endpoint error's traceback would hold the request frame.
    assert error.__cause__ is None
    assert error.__context__ is None
    assert not any(name.endswith("._token_request") for name in _frame_names(error))
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

        assert str(error) == "HTTP 400"
        assert error.error_code == "invalid_request"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_refresh_unreadable_response_carries_no_decoder_text(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=200, content=f"not json {REFRESH_TOKEN}".encode())

        error = await self._refresh_error()

        assert str(error) == "token response could not be read"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_a_refusal_states_no_provider_text(self, httpx_mock: HTTPXMock) -> None:
        """The endpoint chooses this text and can echo a value the request sent, so the status stands in."""
        description = f"token {REFRESH_TOKEN} for secret {CLIENT_SECRET} is not valid"
        httpx_mock.add_response(status_code=400, json={"error": "invalid_request", "error_description": description})

        error = await self._refresh_error()

        assert str(error) == "HTTP 400"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_an_exchange_refusal_states_no_provider_text(self, httpx_mock: HTTPXMock) -> None:
        description = f"code {CODE} does not match verifier {VERIFIER}"
        httpx_mock.add_response(status_code=400, json={"error": "invalid_grant", "error_description": description})

        error = await self._exchange_error()

        assert str(error) == "HTTP 400"
        _assert_carries_no_secret(error, CLIENT_SECRET, CODE, VERIFIER)

    async def test_a_server_error_states_no_provider_text(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=503, json={"error_description": f"retry {REFRESH_TOKEN} later"})

        error = await self._refresh_error()

        assert str(error) == "HTTP 503"
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_an_error_code_shaped_like_no_code_is_reported_as_absent(self, httpx_mock: HTTPXMock) -> None:
        """The field admits any printable text, so a value that is no code carries nothing to branch on."""
        httpx_mock.add_response(status_code=400, json={"error": REFRESH_TOKEN})

        error = await self._refresh_error()

        assert error.error_code == ""
        _assert_carries_no_secret(error, CLIENT_SECRET, REFRESH_TOKEN)

    async def test_an_echo_in_another_encoding_does_not_reach_the_message(self, httpx_mock: HTTPXMock) -> None:
        """A provider chooses the encoding it echoes a sent value in, and the message states no provider text."""
        secret = "s3cr/t+=x"  # pragma: allowlist secret
        httpx_mock.add_response(
            status_code=400,
            json={"error": "invalid_client", "error_description": "bad s3cr%2ft%2b%3dx"},
        )
        client = OAuthClient(_config(client_secret=SecretStr(secret)))

        with pytest.raises(OAuthError) as exc_info:
            await client.refresh_token(REFRESH_TOKEN)

        assert str(exc_info.value) == "HTTP 400"
        _assert_carries_no_secret(exc_info.value, secret, REFRESH_TOKEN)

    @pytest.mark.parametrize(
        "echoed",
        [
            pytest.param("deadbeefcafebabe0123456789abcdef", id="hex of 16 bytes"),  # pragma: allowlist secret
            pytest.param("fedcba9876543210fedcba9876543210fedcba98", id="hex of 20 bytes"),  # pragma: allowlist secret
            pytest.param("3f2504e04f8911d39a0c0305e82c3301", id="a uuid without hyphens"),  # pragma: allowlist secret
            pytest.param("aaaqeayeaudaocajbifqydiob4ibceqt", id="lowercase base32"),  # pragma: allowlist secret
            pytest.param("xoxb-1234-5678-abcdefghijklmnop", id="a provider-prefixed token"),  # pragma: allowlist secret
        ],
    )
    async def test_an_error_code_shaped_like_a_credential_is_reported_as_absent(
        self, httpx_mock: HTTPXMock, echoed: str
    ) -> None:
        """A code is a lowercase identifier, and the forms a credential takes are not one."""
        httpx_mock.add_response(status_code=400, json={"error": echoed})

        error = await self._refresh_error()

        assert error.error_code == ""

    async def test_a_single_word_error_code_is_kept(self, httpx_mock: HTTPXMock) -> None:
        """A provider need not join words to state a code, so one word is a code too."""
        httpx_mock.add_response(status_code=400, json={"error": "overloaded"})

        error = await self._refresh_error()

        assert error.error_code == "overloaded"

    async def test_an_error_member_the_endpoint_left_empty_states_no_code(self, httpx_mock: HTTPXMock) -> None:
        """The token client substitutes an identifier of its own here, which no endpoint sent."""
        httpx_mock.add_response(status_code=400, json={"error": None, "error_description": "x"})

        error = await self._refresh_error()

        assert error.error_code == ""

    async def test_a_refusal_sent_with_a_success_status_is_not_described_as_that_status(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """Some providers refuse with 200 and an error body, and a success status describes no failure."""
        httpx_mock.add_response(status_code=200, json={"error": "invalid_grant"})

        error = await self._refresh_error()

        assert str(error) == "token endpoint returned an error"
        assert error.error_code == "invalid_grant"

    async def test_a_code_containing_a_sent_value_is_reported_whole(self, httpx_mock: HTTPXMock) -> None:
        """A refresh token of "grant" sits inside "invalid_grant", which stays the code it is."""
        httpx_mock.add_response(status_code=400, json={"error": "invalid_grant"})
        client = OAuthClient(_config())

        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token("grant")

        assert exc_info.value.error_code == "invalid_grant"
        assert exc_info.value.kind is FailureKind.REJECTED


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
            await client.fetch_identity(FreshTokenSet(access_token=ACCESS_TOKEN))

        assert str(exc_info.value) == f"Failed to fetch identity: {kind}"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)

    async def test_identity_handler_unexpected_error_carries_no_text(self) -> None:
        class BrokenHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                raise RuntimeError(f"{RAW_TEXT} {material.access_token}")

        client = OAuthClient(_config(), identity_handler=BrokenHandler())
        with pytest.raises(IdentityFetchError) as exc_info:
            await client.fetch_identity(FreshTokenSet(access_token=ACCESS_TOKEN))

        assert str(exc_info.value) == "Failed to fetch identity"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)

    async def test_configuration_error_from_a_revocation_handler_keeps_its_class_and_message(self) -> None:
        class MisconfiguredHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                raise ConfigurationError("revocation needs client authentication")

        client = OAuthClient(_config(), revocation_handler=MisconfiguredHandler())
        with pytest.raises(ConfigurationError) as exc_info:
            await client.revoke_token(ACCESS_TOKEN)

        assert not isinstance(exc_info.value, RevocationError)
        assert exc_info.value.kind is FailureKind.CONFIGURATION
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None
        assert str(exc_info.value) == "revocation needs client authentication"
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)

    async def test_configuration_error_from_an_identity_handler_keeps_its_class_and_message(self) -> None:
        class MisconfiguredHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                raise ConfigurationError("config names a different issuer")

        client = OAuthClient(_config(), identity_handler=MisconfiguredHandler())
        with pytest.raises(ConfigurationError) as exc_info:
            await client.fetch_identity(FreshTokenSet(access_token=ACCESS_TOKEN))

        assert not isinstance(exc_info.value, IdentityFetchError)
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
        # The handler's frames hold the token, so they must not stay on the error's traceback.
        assert not any(name.startswith("ChainingHandler") for name in _frame_names(exc_info.value))
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
            await client.fetch_identity(FreshTokenSet(access_token=ACCESS_TOKEN))

        assert str(exc_info.value) == "Custom identity failed"
        assert not any(name.startswith("ChainingHandler") for name in _frame_names(exc_info.value))
        _assert_carries_no_secret(exc_info.value, ACCESS_TOKEN)
