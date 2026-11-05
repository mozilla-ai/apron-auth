"""No frame local on a failure's traceback states a credential, because error reporters capture them.

An error reporter such as Sentry records the local variables of every frame a traceback holds. A
credential bound to one of those is therefore recorded, which no rule about a message or an
exception chain reaches, so the type carrying it has to state nothing itself.

Each test holds both halves of the rule: the credential reached the request, and no local states it.
A credential that never reaches the request would satisfy the second half on its own.
"""

from __future__ import annotations

import os
from collections.abc import Callable

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.models import IdentityMaterial, Provider, ProviderConfig
from apron_auth.providers import github, google, hubspot, notion, revocation_handler_for, slack
from apron_auth.providers._revocation import StandardRevocationHandler
from apron_auth.providers.salesforce import SalesforceIdentityHandler

# A token value distinctive enough that finding it in a repr cannot be a coincidence.
TOKEN = "s3cr3t-live-access-token"  # pragma: allowlist secret

# The client secret the configuration carries, which a revocation request presents as HTTP Basic.
CLIENT_SECRET = "s3cr3t-client-secret"  # pragma: allowlist secret

# The path segment every module of this library shares, which marks a frame as its own.
LIBRARY_SOURCE = f"{os.sep}apron_auth{os.sep}"

# A status no revocation handler reads as the token revoked, so every handler raises.
REFUSED_STATUS = 500

# The preset of each provider whose revocation handler states the token in a place of its own.
PRESETS: dict[Provider, Callable[..., ProviderConfig]] = {
    Provider.GITHUB: github.preset,
    Provider.GOOGLE: google.preset,
    Provider.HUBSPOT: hubspot.preset,
    Provider.NOTION: notion.preset,
    Provider.SLACK: slack.preset,
}


def _config(provider: Provider) -> ProviderConfig:
    return PRESETS[provider](client_id="cid", client_secret=CLIENT_SECRET, scopes=["chat:write"])


def _standard_config() -> ProviderConfig:
    return ProviderConfig(
        client_id="cid",
        client_secret=CLIENT_SECRET,
        authorize_url="https://auth.example.com/authorize",
        token_url="https://auth.example.com/token",
        revocation_url="https://auth.example.com/revoke",
    )


def _recording_transport(sent: list[httpx.Request]) -> Callable[[str], httpx.AsyncBaseTransport]:
    """Record every request and answer each with a status no handler reads as the token revoked."""

    def factory(_url: str) -> httpx.AsyncBaseTransport:
        async def handle(request: httpx.Request) -> httpx.Response:
            sent.append(request)
            return httpx.Response(REFUSED_STATUS, json={"error": "server_error"})

        return httpx.MockTransport(handle)

    return factory


def _request_text(request: httpx.Request) -> str:
    """Return everything the request states, so a token in any part of it is found."""
    headers = "".join(f"{name}:{value}" for name, value in request.headers.items())
    return f"{request.url}{headers}{request.content.decode(errors='replace')}"


def _locals_stating(exc: BaseException, value: str) -> list[str]:
    """Return one name per frame local of this library on the traceback whose repr states ``value``.

    Only this library's own frames are walked, because a caller's locals are the caller's to hold.
    The test calling this holds the sent requests itself, which is one such local.

    Args:
        exc: The error whose traceback to walk.
        value: The credential that must appear in no local.

    Returns:
        A description of each local that states it, empty when none does.
    """
    stated: list[str] = []
    frames = exc.__traceback__
    while frames is not None:
        frame = frames.tb_frame
        if LIBRARY_SOURCE not in frame.f_code.co_filename:
            frames = frames.tb_next
            continue
        for name, held in frame.f_locals.items():
            try:
                shown = repr(held)
            except Exception:  # noqa: BLE001
                continue
            if value in shown:
                stated.append(f"{frame.f_code.co_name}.{name}")
        frames = frames.tb_next
    return stated


class TestARevocationFailure:
    """Test that a failed revocation leaves no credential in a frame local."""

    async def test_the_standard_handler_states_no_token(self) -> None:
        sent: list[httpx.Request] = []
        handler = StandardRevocationHandler(transport_factory=_recording_transport(sent))

        with pytest.raises(Exception) as caught:  # noqa: B017, PT011
            await handler.revoke(SecretStr(TOKEN), _standard_config())

        assert TOKEN in _request_text(sent[0])
        assert _locals_stating(caught.value, TOKEN) == []

    async def test_the_standard_handler_states_no_client_secret(self) -> None:
        """The request presents the secret as HTTP Basic, so what builds the request holds it too."""
        sent: list[httpx.Request] = []
        handler = StandardRevocationHandler(transport_factory=_recording_transport(sent))

        with pytest.raises(Exception) as caught:  # noqa: B017, PT011
            await handler.revoke(SecretStr(TOKEN), _standard_config())

        assert sent[0].headers.get("authorization", "").startswith("Basic ")
        assert _locals_stating(caught.value, CLIENT_SECRET) == []

    @pytest.mark.parametrize("provider", list(PRESETS), ids=lambda provider: provider.value)
    async def test_a_provider_handler_states_no_token(self, provider: Provider) -> None:
        """Each provider states the token in a place of its own, so each one is held to the rule."""
        sent: list[httpx.Request] = []
        config = _config(provider)
        handler = revocation_handler_for(config, transport_factory=_recording_transport(sent))
        assert handler is not None

        with pytest.raises(Exception) as caught:  # noqa: B017, PT011
            await handler.revoke(SecretStr(TOKEN), config)

        assert TOKEN in _request_text(sent[0])
        assert _locals_stating(caught.value, TOKEN) == []


class TestAnIdentityFailure:
    """Test that a failed identity fetch leaves no token in a frame local."""

    async def test_the_handler_states_no_access_token(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://login.salesforce.com/services/oauth2/userinfo",
            status_code=REFUSED_STATUS,
            json={"error": "server_error"},
        )
        config = ProviderConfig(
            provider=Provider.SALESFORCE,
            client_id="cid",
            client_secret=CLIENT_SECRET,
            authorize_url="https://login.salesforce.com/services/oauth2/authorize",
            token_url="https://login.salesforce.com/services/oauth2/token",
        )

        with pytest.raises(Exception) as caught:  # noqa: B017, PT011
            await SalesforceIdentityHandler().fetch_identity(IdentityMaterial(access_token=TOKEN), config)

        assert httpx_mock.get_request().headers["authorization"] == f"Bearer {TOKEN}"
        assert _locals_stating(caught.value, TOKEN) == []
