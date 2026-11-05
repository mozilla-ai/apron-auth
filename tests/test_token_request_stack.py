"""The token request's client authentication and its HTTP stack are this library's own contract.

A third-party OAuth client decides which HTTP package it is built on. That decision governs both the
transport shape a caller may supply and the exception classes a failed request raises, so holding it
puts a dependency's private choice inside this library's public contract.
"""

from __future__ import annotations

import base64
import sys
import time
from urllib.parse import parse_qs

import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.client import OAuthClient
from apron_auth.models import (
    AuthorizationCallback,
    OAuthPendingState,
    ProviderConfig,
    TokenEndpointAuthMethod,
)

CLIENT_ID = "test-client"
CLIENT_SECRET = "test-secret"  # pragma: allowlist secret
# A secret holding characters outside latin-1, which only a UTF-8 encoding of the credentials carries.
NON_LATIN1_SECRET = "secret-中文-é"  # pragma: allowlist secret
# A secret holding every character that form encoding escapes, which RFC 6749 section 2.3.1 requires
# escaped before the credentials are base64-encoded.
RESERVED_SECRET = "a+b c&d=e/f"  # pragma: allowlist secret
TOKEN_URL = "https://provider.example.com/token"
# The modules that hold a third-party OAuth client, which the token request must not need.
THIRD_PARTY_CLIENT_MODULES = (
    "authlib.integrations",
    "authlib.integrations.base_client",
    "authlib.integrations.base_client.errors",
    "authlib.integrations.httpx_client",
)


def _config(**overrides: object) -> ProviderConfig:
    defaults: dict[str, object] = {
        "client_id": CLIENT_ID,
        "client_secret": SecretStr(CLIENT_SECRET),
        "authorize_url": "https://provider.example.com/authorize",
        "token_url": TOKEN_URL,
        "scopes": ["email"],
    }
    defaults.update(overrides)
    return ProviderConfig(**defaults)


def _pending_state() -> OAuthPendingState:
    return OAuthPendingState(
        state="pending-state",
        redirect_uri="https://app.example.com/callback",
        code_verifier="code-verifier-for-these-tests",
        created_at=time.time(),
        openid_requested=False,
    )


async def _exchange(config: ProviderConfig) -> None:
    client = OAuthClient(config)
    await client.exchange_code(
        AuthorizationCallback(code="auth-code-123", state="pending-state"), pending_state=_pending_state()
    )


def _basic_credentials(header: str) -> str:
    """Return the decoded credentials of a Basic authorization header.

    Args:
        header: The header value the request sent.

    Returns:
        The ``id:secret`` pair the header carries, still form-encoded.
    """
    scheme, _, encoded = header.partition(" ")
    assert scheme == "Basic"
    return base64.b64decode(encoded).decode()


def _sent_form(httpx_mock: HTTPXMock) -> dict[str, list[str]]:
    """Return the form fields of the token request.

    Args:
        httpx_mock: The mock that answered the request.

    Returns:
        Each field name sent, with its values.
    """
    request = httpx_mock.get_request()
    assert request is not None
    return parse_qs(request.content.decode())


@pytest.fixture
def token_endpoint(httpx_mock: HTTPXMock) -> HTTPXMock:
    """Answer one token request with a minimal success body."""
    httpx_mock.add_response(url=TOKEN_URL, json={"access_token": "access-abc", "token_type": "Bearer"})
    return httpx_mock


class TestTokenRequestClientAuthentication:
    """The method the config names decides where the credentials go, and nothing else does.

    The tests follow the methods in the order ProviderConfig declares them, rather than A-Z.
    """

    async def test_basic_sends_the_credentials_as_a_header(self, token_endpoint: HTTPXMock) -> None:
        await _exchange(_config(token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC))
        request = token_endpoint.get_request()
        assert request is not None
        assert _basic_credentials(request.headers["authorization"]) == f"{CLIENT_ID}:{CLIENT_SECRET}"
        assert "client_secret" not in _sent_form(token_endpoint)

    async def test_basic_sends_a_reserved_character_in_the_secret_unencoded(self, token_endpoint: HTTPXMock) -> None:
        """NOTE: RFC 6749 section 2.3.1 asks for form encoding of each credential before the base64 step.
        The request encodes neither, which is what a provider reading the secret verbatim accepts.
        """
        await _exchange(
            _config(
                client_secret=SecretStr(RESERVED_SECRET),
                token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            )
        )
        request = token_endpoint.get_request()
        assert request is not None
        assert _basic_credentials(request.headers["authorization"]) == f"{CLIENT_ID}:{RESERVED_SECRET}"

    async def test_basic_encodes_the_credentials_as_utf_8(self, token_endpoint: HTTPXMock) -> None:
        """RFC 7617 section 2.1 names UTF-8 as the charset a client should encode the credentials with."""
        await _exchange(
            _config(
                client_secret=SecretStr(NON_LATIN1_SECRET),
                token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            )
        )
        request = token_endpoint.get_request()
        assert request is not None
        assert _basic_credentials(request.headers["authorization"]) == f"{CLIENT_ID}:{NON_LATIN1_SECRET}"

    async def test_post_sends_the_credentials_as_form_fields(self, token_endpoint: HTTPXMock) -> None:
        await _exchange(_config(token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_POST))
        request = token_endpoint.get_request()
        assert request is not None
        assert "authorization" not in request.headers
        form = _sent_form(token_endpoint)
        assert form["client_id"] == [CLIENT_ID]
        assert form["client_secret"] == [CLIENT_SECRET]

    async def test_a_public_client_sends_its_identifier_and_no_secret(self, token_endpoint: HTTPXMock) -> None:
        await _exchange(
            _config(client_secret=None, token_endpoint_auth_method=TokenEndpointAuthMethod.NONE),
        )
        request = token_endpoint.get_request()
        assert request is not None
        assert "authorization" not in request.headers
        form = _sent_form(token_endpoint)
        assert form["client_id"] == [CLIENT_ID]
        assert "client_secret" not in form


class TestTokenRequestContentNegotiation:
    """The request states the body it accepts, because an endpoint may answer a form-encoded one otherwise."""

    async def test_the_request_asks_for_json(self, token_endpoint: HTTPXMock) -> None:
        await _exchange(_config())
        request = token_endpoint.get_request()
        assert request is not None
        assert request.headers["accept"] == "application/json"


class TestTokenRequestHttpStack:
    """The exchange holds this library's own HTTP client, so no dependency decides the stack for it."""

    async def test_the_exchange_needs_no_third_party_oauth_client(
        self, token_endpoint: HTTPXMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A third-party client that cannot be imported must not stop the exchange.

        NOTE: A ``None`` entry in ``sys.modules`` makes the import raise, which stands in for the
        dependency binding itself to an HTTP package this library does not use.
        """
        for module in THIRD_PARTY_CLIENT_MODULES:
            monkeypatch.setitem(sys.modules, module, None)
        await _exchange(_config())
