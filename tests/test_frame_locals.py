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
from importlib import import_module
from typing import Any, TypeAlias

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.models import IdentityMaterial, Provider, ProviderConfig, SecretToken
from apron_auth.providers import github, google, hubspot, notion, revocation_handler_for, slack
from apron_auth.providers._revocation import StandardRevocationHandler

# One identity handler with the configuration it accepts, built on demand so no import runs at collection.
IdentityCase: TypeAlias = Callable[[], "tuple[Any, ProviderConfig]"]

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


def _identity_case(module_name: str, handler_name: str, preset_name: str, scopes: list[str]) -> IdentityCase:
    """Build one handler and the configuration its own host gate accepts."""

    def build() -> tuple[Any, ProviderConfig]:
        module = import_module(f"apron_auth.providers.{module_name}")
        preset = getattr(module, preset_name)
        config = preset(client_id="cid", client_secret=CLIENT_SECRET, scopes=scopes)
        return getattr(module, handler_name)(), config

    return build


# Every bundled identity handler, keyed by the provider whose handler it is.
IDENTITY_CASES: dict[Provider, IdentityCase] = {
    Provider.ATLASSIAN: _identity_case("atlassian", "AtlassianIdentityHandler", "preset", ["read:me"]),
    Provider.GITHUB: _identity_case("github", "GitHubIdentityHandler", "preset", ["read:user"]),
    Provider.GOOGLE: _identity_case("google", "GoogleIdentityHandler", "preset", ["openid"]),
    Provider.HUBSPOT: _identity_case("hubspot", "HubSpotIdentityHandler", "preset", ["oauth"]),
    Provider.LINEAR: _identity_case("linear", "LinearIdentityHandler", "preset", ["read"]),
    Provider.MICROSOFT: _identity_case("microsoft", "MicrosoftIdentityHandler", "preset", ["openid"]),
    Provider.NOTION: _identity_case("notion", "NotionIdentityHandler", "preset", ["read"]),
    Provider.SALESFORCE: _identity_case("salesforce", "SalesforceIdentityHandler", "preset", ["openid"]),
    Provider.SLACK: _identity_case("slack", "SlackIdentityHandler", "sign_in_preset", ["openid"]),
    Provider.TYPEFORM: _identity_case("typeform", "TypeformIdentityHandler", "preset", ["accounts:read"]),
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
            await handler.revoke(SecretToken(TOKEN), _standard_config())

        assert TOKEN in _request_text(sent[0])
        assert _locals_stating(caught.value, TOKEN) == []

    async def test_the_standard_handler_states_no_client_secret(self) -> None:
        """The request presents the secret as HTTP Basic, so what builds the request holds it too."""
        sent: list[httpx.Request] = []
        handler = StandardRevocationHandler(transport_factory=_recording_transport(sent))

        with pytest.raises(Exception) as caught:  # noqa: B017, PT011
            await handler.revoke(SecretToken(TOKEN), _standard_config())

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
            await handler.revoke(SecretToken(TOKEN), config)

        assert TOKEN in _request_text(sent[0])
        assert _locals_stating(caught.value, TOKEN) == []


class TestAnIdentityFailure:
    """Test that a failed identity fetch leaves no token in a frame local."""

    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False, can_send_already_matched_responses=True)
    @pytest.mark.parametrize("provider", list(IDENTITY_CASES), ids=lambda provider: provider.value)
    async def test_a_provider_handler_states_no_access_token(self, provider: Provider, httpx_mock: HTTPXMock) -> None:
        """Each handler presents the token its own way, so each one is held to the rule.

        One handler states the token in the request line and another in a header, and one sends two
        requests with it, so no single shape stands in for the rest.
        """
        httpx_mock.add_response(status_code=REFUSED_STATUS, json={"error": "server_error"})
        handler, config = IDENTITY_CASES[provider]()

        with pytest.raises(Exception) as caught:  # noqa: B017, PT011
            await handler.fetch_identity(IdentityMaterial(access_token=TOKEN), config)

        assert TOKEN in "".join(_request_text(request) for request in httpx_mock.get_requests())
        assert _locals_stating(caught.value, TOKEN) == []
