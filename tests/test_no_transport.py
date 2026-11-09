"""The connection a caller's transport factory states, and what every outbound path does without one."""

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr

from apron_auth import mcp
from apron_auth._discovery import NoTransportError, chosen_transport
from apron_auth.client import OAuthClient
from apron_auth.errors import (
    IdentityFetchError,
    McpDiscoveryError,
    OidcDiscoveryError,
    RevocationError,
    TokenRefreshError,
)
from apron_auth.models import Provider, ProviderConfig, SecretToken, TimeoutPolicy
from apron_auth.providers._identity_requests import identity_transport
from apron_auth.providers._jwks import IssuerSigningKeys, SigningAlgorithm
from apron_auth.providers._openid_documents import fetch_document

_KEYS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
_OPENID_URL = "https://issuer.example.com/.well-known/openid-configuration"


def _forgetful_factory(url: str) -> httpx.AsyncBaseTransport | None:
    """Return a transport for one host and, as a factory with a missing return does, nothing for the rest."""
    if url.startswith("https://allowed.example.com"):
        return httpx.MockTransport(lambda request: httpx.Response(200))
    return None


def _config() -> ProviderConfig:
    return ProviderConfig(
        provider=Provider.GOOGLE,
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        revocation_url="https://oauth2.googleapis.com/revoke",
    )


class TestChosenTransport:
    def test_a_caller_who_gave_no_factory_gets_the_default_connection(self) -> None:
        assert chosen_transport(None, "https://api.example.com/me") is None

    def test_the_transport_a_factory_states_is_returned(self) -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(200))
        assert chosen_transport(lambda url: transport, "https://api.example.com/me") is transport

    def test_a_factory_that_states_no_transport_is_refused(self) -> None:
        with pytest.raises(NoTransportError):
            chosen_transport(_forgetful_factory, "https://api.example.com/me")


class TestEveryOutboundPathFailsClosed:
    """A factory states the connection of every request carrying a credential.

    A path that fell back to the default connection here would send that request on a connection the
    factory was given to replace, so each one refuses instead, in the error its own callers read.
    """

    def test_the_identity_fetch_refuses(self) -> None:
        with pytest.raises(IdentityFetchError) as refusal:
            identity_transport(_forgetful_factory, "https://api.github.com/user", "GitHub identity")
        assert refusal.value.retryable is False

    async def test_the_token_request_refuses(self) -> None:
        client = OAuthClient(config=_config(), transport_factory=_forgetful_factory)
        with pytest.raises(TokenRefreshError) as refusal:
            await client.refresh_token("refresh-abc")
        assert refusal.value.retryable is False

    async def test_revocation_refuses(self) -> None:
        client = OAuthClient(config=_config(), transport_factory=_forgetful_factory)
        with pytest.raises(RevocationError) as refusal:
            await client.revoke_token(SecretToken("access-abc"))
        assert refusal.value.retryable is False

    async def test_the_signing_key_fetch_refuses(self) -> None:
        keys = IssuerSigningKeys(_KEYS_URL, algorithms=(SigningAlgorithm.RS256,), transport_factory=_forgetful_factory)
        with pytest.raises(IdentityFetchError) as refusal:
            await keys._fetch(TimeoutPolicy())
        assert refusal.value.retryable is False

    async def test_openid_discovery_refuses(self) -> None:
        with pytest.raises(OidcDiscoveryError) as refusal:
            await fetch_document(_OPENID_URL, _forgetful_factory, TimeoutPolicy())
        assert refusal.value.retryable is False

    async def test_mcp_discovery_refuses(self) -> None:
        with pytest.raises(McpDiscoveryError) as refusal:
            await mcp.discover("https://mcp.example.com", transport_factory=_forgetful_factory)
        assert refusal.value.retryable is False
