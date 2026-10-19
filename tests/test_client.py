from __future__ import annotations

import asyncio
import base64
import json
import time
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.client import OAuthClient
from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    IdentityNotSupportedError,
    IdentityScopeNotGrantedError,
    IdTokenValidationError,
    IssuerValidationError,
    NonceValidationError,
    RevocationError,
    StateError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import (
    IdentityMaterial,
    IdentityProfile,
    OAuthPendingState,
    ProviderConfig,
    TenancyContext,
    TokenSet,
)
from apron_auth.pkce import generate_code_challenge


def _make_config(**overrides: object) -> ProviderConfig:
    defaults = {
        "client_id": "test-client",
        "client_secret": SecretStr("test-secret"),
        "authorize_url": "https://provider.example.com/authorize",
        "token_url": "https://provider.example.com/token",
        "scopes": ["openid", "email"],
    }
    defaults.update(overrides)
    return ProviderConfig(**defaults)


def _make_oauth_config(**overrides: object) -> ProviderConfig:
    """Return a config whose authorization request asks for no ``openid`` scope, so no nonce is checked."""
    return _make_config(scopes=["email"], **overrides)


def _pending_state(**overrides: object) -> OAuthPendingState:
    defaults = {
        "state": "pending-state",
        "redirect_uri": "https://app.example.com/callback",
        "created_at": time.time(),
    }
    defaults.update(overrides)
    return OAuthPendingState(**defaults)


def _id_token(claims: object) -> str:
    """Return a compact token carrying ``claims``, with a signature nothing here checks."""
    segments = [{"alg": "RS256"}, claims]
    encoded = [base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b"=").decode() for part in segments]
    return ".".join([*encoded, "c2ln"])


def _openid_claims(**claims: object) -> dict[str, object]:
    """Return ID token claims issued to the test client and still valid, with ``claims`` on top."""
    return {"sub": "u-1", "aud": "test-client", "exp": int(time.time()) + 300, **claims}


class TestGetAuthorizationUrl:
    async def test_returns_url_and_pending_state(self):
        config = _make_config()
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        assert url.startswith("https://provider.example.com/authorize?")
        assert isinstance(pending_state, OAuthPendingState)
        assert pending_state.redirect_uri == "https://app.example.com/callback"

    async def test_url_contains_required_params(self):
        config = _make_config()
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["test-client"]
        assert params["response_type"] == ["code"]
        assert params["redirect_uri"] == ["https://app.example.com/callback"]
        assert params["scope"] == ["openid email"]
        assert "state" in params

    async def test_pkce_included_when_enabled(self):
        config = _make_config(use_pkce=True)
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["code_challenge_method"] == ["S256"]
        assert "code_challenge" in params
        assert pending_state.code_verifier is not None

    async def test_pkce_excluded_when_disabled(self):
        config = _make_config(use_pkce=False)
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert "code_challenge" not in params
        assert pending_state.code_verifier is None

    async def test_extra_params_included(self):
        config = _make_config(extra_params={"access_type": "offline", "prompt": "consent"})
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["access_type"] == ["offline"]
        assert params["prompt"] == ["consent"]

    async def test_resource_included_when_set(self) -> None:
        config = _make_config(resource="https://mcp.example.com/")
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["resource"] == ["https://mcp.example.com/"]

    async def test_resource_absent_when_unset(self) -> None:
        config = _make_config()
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert "resource" not in params

    async def test_resource_not_overridden_by_extra_params(self) -> None:
        """The resource wins even for a config that was built without validation."""
        config = _make_config(resource="https://mcp.example.com/").model_copy(
            update={"extra_params": {"resource": "https://attacker.example.com/"}}
        )
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["resource"] == ["https://mcp.example.com/"]

    async def test_scope_separator_applied(self):
        config = _make_config(scopes=["read", "write"], scope_separator=",")
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["scope"] == ["read,write"]

    async def test_redirect_uri_from_config(self):
        config = _make_config(redirect_uri="https://app.example.com/default-callback")
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url()
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["redirect_uri"] == ["https://app.example.com/default-callback"]
        assert pending_state.redirect_uri == "https://app.example.com/default-callback"

    async def test_method_redirect_uri_overrides_config(self):
        config = _make_config(redirect_uri="https://app.example.com/default")
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/override",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["redirect_uri"] == ["https://app.example.com/override"]
        assert pending_state.redirect_uri == "https://app.example.com/override"

    async def test_no_redirect_uri_raises(self):
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(ConfigurationError, match="redirect_uri"):
            await client.get_authorization_url()

    async def test_state_store_save_called(self):
        config = _make_config()
        store = AsyncMock()
        store.save = AsyncMock()
        client = OAuthClient(config=config, state_store=store)
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        store.save.assert_awaited_once()
        saved_state = store.save.call_args[0][0]
        assert saved_state.state == pending_state.state

    async def test_state_store_not_called_when_absent(self):
        config = _make_config()
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        assert pending_state is not None

    async def test_metadata_defaults_to_empty(self):
        config = _make_config()
        client = OAuthClient(config=config)
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
        )
        assert pending_state.metadata == {}

    async def test_metadata_attached_to_pending_state(self):
        config = _make_config()
        client = OAuthClient(config=config)
        meta = {"user_id": "U123", "tenant_id": "T456"}
        _, pending_state = await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
            metadata=meta,
        )
        assert pending_state.metadata == meta

    async def test_metadata_saved_to_state_store(self):
        config = _make_config()
        store = AsyncMock()
        store.save = AsyncMock()
        client = OAuthClient(config=config, state_store=store)
        meta = {"user_id": "U123"}
        await client.get_authorization_url(
            redirect_uri="https://app.example.com/callback",
            metadata=meta,
        )
        saved_state = store.save.call_args[0][0]
        assert saved_state.metadata == meta

    async def test_state_is_unique_per_call(self):
        config = _make_config()
        client = OAuthClient(config=config)
        _, s1 = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        _, s2 = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        assert s1.state != s2.state

    async def test_nonce_sent_when_scopes_include_openid(self) -> None:
        client = OAuthClient(config=_make_config(scopes=["email", "openid"]))
        url, pending_state = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        params = parse_qs(urlparse(url).query)
        assert pending_state.nonce
        assert params["nonce"] == [pending_state.nonce]

    async def test_nonce_absent_without_openid_scope(self) -> None:
        client = OAuthClient(config=_make_config(scopes=["email"]))
        url, pending_state = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        params = parse_qs(urlparse(url).query)
        assert "nonce" not in params
        assert pending_state.nonce is None

    async def test_nonce_not_overridden_by_extra_params(self) -> None:
        """The nonce wins even for a config that was built without validation."""
        config = _make_config().model_copy(update={"extra_params": {"nonce": "chosen-nonce"}})
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        params = parse_qs(urlparse(url).query)
        assert pending_state.nonce != "chosen-nonce"
        assert params["nonce"] == [pending_state.nonce]

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("client_id", "test-client"),
            ("code_challenge_method", "S256"),
            ("redirect_uri", "https://app.example.com/callback"),
            ("response_type", "code"),
        ],
    )
    async def test_client_parameters_not_overridden_by_extra_params(self, name: str, expected: str) -> None:
        """The parameters the client sets win even for a config that was built without validation."""
        config = _make_config().model_copy(update={"extra_params": {name: "chosen-value"}})
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        params = parse_qs(urlparse(url).query)
        assert params[name] == [expected]

    async def test_session_binding_parameters_not_overridden_by_extra_params(self) -> None:
        """The state and the PKCE challenge come from the pending state, not from the config."""
        config = _make_config().model_copy(update={"extra_params": {"state": "chosen", "code_challenge": "chosen"}})
        client = OAuthClient(config=config)
        url, pending_state = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        params = parse_qs(urlparse(url).query)
        assert pending_state.code_verifier is not None
        assert params["state"] == [pending_state.state]
        assert params["code_challenge"] == [generate_code_challenge(pending_state.code_verifier)]

    @pytest.mark.parametrize("name", ["request", "request_uri", "resource"])
    async def test_reserved_parameters_the_client_does_not_set_are_dropped(self, name: str) -> None:
        """A reserved parameter the client has no value for is dropped, not sent from the config."""
        config = _make_config().model_copy(update={"extra_params": {name: "chosen-value"}})
        client = OAuthClient(config=config)
        url, _ = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        assert name not in parse_qs(urlparse(url).query)

    async def test_reserved_parameters_are_dropped_from_the_authorize_url_query(self) -> None:
        """A reserved parameter in the URL's own query is dropped, whether or not the client sets it."""
        authorize_url = "https://provider.example.com/authorize?state=chosen-value&request_uri=chosen-value"
        client = OAuthClient(config=_make_config(authorize_url=authorize_url))
        url, pending_state = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        params = parse_qs(urlparse(url).query)
        assert params["state"] == [pending_state.state]
        assert "request_uri" not in params

    async def test_nonce_not_overridden_by_authorize_url_query(self) -> None:
        client = OAuthClient(
            config=_make_config(
                scopes=["openid", "email"], authorize_url="https://provider.example.com/authorize?nonce=fixed"
            )
        )
        url, pending_state = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        params = parse_qs(urlparse(url).query)
        assert params["nonce"] == [pending_state.nonce]

    @pytest.mark.parametrize(
        ("overrides", "sends_nonce"),
        [
            ({"scopes": [], "extra_params": {"scope": "openid email"}}, True),
            ({"scopes": [], "scope_separator": ",", "extra_params": {"scope": "openid,email"}}, True),
            ({"scopes": [], "scope_separator": ",", "extra_params": {"scope": "openid profile"}}, True),
            ({"scopes": [], "extra_params": {"scope": "openid,email"}}, True),
            ({"scopes": ["openid", "email"], "scope_separator": ", "}, True),
            ({"scopes": ["openid"], "scope_separator": ""}, True),
            ({"scopes": [], "authorize_url": "https://provider.example.com/authorize?scope=openid"}, True),
            ({"scopes": ["openid"], "extra_params": {"scope": "email"}}, False),
            ({"scopes": ["openidish"]}, False),
        ],
        ids=[
            "extra-params",
            "extra-params-comma",
            "space-delimited",
            "comma-with-space-separator",
            "separator-with-space",
            "empty-separator",
            "authorize-url-query",
            "overridden",
            "lookalike",
        ],
    )
    async def test_nonce_follows_the_scope_the_request_sends(
        self, overrides: dict[str, object], sends_nonce: bool
    ) -> None:
        client = OAuthClient(config=_make_config(**overrides))
        url, pending_state = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        params = parse_qs(urlparse(url).query)
        assert ("nonce" in params) is sends_nonce
        assert (pending_state.nonce is not None) is sends_nonce

    async def test_repeated_authorize_url_scope_is_kept(self) -> None:
        url_with_scopes = "https://provider.example.com/authorize?scope=openid&scope=email"
        client = OAuthClient(config=_make_config(scopes=[], authorize_url=url_with_scopes))
        url, pending_state = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        params = parse_qs(urlparse(url).query)
        assert params["scope"] == ["openid", "email"]
        assert params["nonce"] == [pending_state.nonce]

    async def test_nonce_is_unique_per_call(self) -> None:
        client = OAuthClient(config=_make_config())
        _, s1 = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        _, s2 = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        assert s1.nonce != s2.nonce

    async def test_nonce_saved_to_state_store(self) -> None:
        store = AsyncMock()
        store.save = AsyncMock()
        client = OAuthClient(config=_make_config(), state_store=store)
        _, pending_state = await client.get_authorization_url(redirect_uri="https://app.example.com/callback")
        saved_state = store.save.call_args[0][0]
        assert saved_state.nonce == pending_state.nonce


class TestExchangeCode:
    async def test_exchange_with_a_caller_kept_pending_state(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "access-abc",
                "token_type": "Bearer",
                "refresh_token": "refresh-xyz",
                "expires_in": 3600,
                "scope": "openid email",
            },
        )
        config = _make_oauth_config()
        client = OAuthClient(config=config)
        tokens = await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        assert isinstance(tokens, TokenSet)
        assert tokens.access_token == "access-abc"
        assert tokens.refresh_token == "refresh-xyz"
        assert tokens.expires_in == 3600
        assert tokens.expires_at is not None
        assert tokens.scope == "openid email"

    async def test_exchange_with_pkce(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config()
        client = OAuthClient(config=config)
        await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(code_verifier="test-verifier"),
        )
        request = httpx_mock.get_request()
        assert b"code_verifier=test-verifier" in request.content

    async def test_exchange_includes_resource_when_set(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config(resource="https://mcp.example.com/")
        client = OAuthClient(config=config)
        await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        request = httpx_mock.get_request()
        body = parse_qs(request.content.decode())
        assert body["resource"] == ["https://mcp.example.com/"]

    async def test_exchange_omits_resource_when_unset(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config()
        client = OAuthClient(config=config)
        await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        request = httpx_mock.get_request()
        assert b"resource" not in request.content

    async def test_exchange_with_state_store(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        pending = OAuthPendingState(
            state="stored-state",
            redirect_uri="https://app.example.com/callback",
            code_verifier="stored-verifier",
            created_at=time.time(),
        )
        store = AsyncMock()
        store.consume = AsyncMock(return_value=pending)
        config = _make_oauth_config()
        client = OAuthClient(config=config, state_store=store)
        tokens = await client.exchange_code(code="auth-code-123", state="stored-state")
        store.consume.assert_awaited_once_with("stored-state")
        assert tokens.access_token == "access-abc"

    async def test_exchange_auto_consume_preserves_context(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        pending = OAuthPendingState(
            state="stored-state",
            redirect_uri="https://app.example.com/callback",
            code_verifier="stored-verifier",
            created_at=time.time(),
            metadata={"user_id": "U123", "tenant_id": "T456"},
        )
        store = AsyncMock()
        store.consume = AsyncMock(return_value=pending)
        config = _make_oauth_config()
        client = OAuthClient(config=config, state_store=store)
        tokens = await client.exchange_code(code="auth-code-123", state="stored-state")
        assert tokens.context == {"user_id": "U123", "tenant_id": "T456"}

    async def test_exchange_auto_consume_empty_metadata(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        pending = OAuthPendingState(
            state="stored-state",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
        )
        store = AsyncMock()
        store.consume = AsyncMock(return_value=pending)
        config = _make_oauth_config()
        client = OAuthClient(config=config, state_store=store)
        tokens = await client.exchange_code(code="auth-code-123", state="stored-state")
        assert tokens.context == {}

    async def test_exchange_pending_state_without_metadata_has_empty_context(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config()
        client = OAuthClient(config=config)
        tokens = await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        assert tokens.context == {}

    async def test_exchange_pending_state_metadata_becomes_context(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        client = OAuthClient(config=_make_oauth_config())
        tokens = await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(metadata={"user_id": "U123"}),
        )
        assert tokens.context == {"user_id": "U123"}

    async def test_exchange_sends_the_pending_state_redirect_uri_and_verifier(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        client = OAuthClient(config=_make_oauth_config())
        await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(redirect_uri="https://app.example.com/other", code_verifier="verifier"),
        )
        body = parse_qs(httpx_mock.get_request().content.decode())
        assert body["redirect_uri"] == ["https://app.example.com/other"]
        assert body["code_verifier"] == ["verifier"]

    async def test_exchange_leaves_out_an_empty_redirect_uri(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        client = OAuthClient(config=_make_oauth_config())
        await client.exchange_code(
            code="auth-code-123", state="pending-state", pending_state=_pending_state(redirect_uri="")
        )
        assert "redirect_uri" not in parse_qs(httpx_mock.get_request().content.decode(), keep_blank_values=True)

    async def test_exchange_sends_the_stored_redirect_uri_and_verifier(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        store = AsyncMock()
        store.consume = AsyncMock(return_value=_pending_state(code_verifier="stored-verifier"))
        client = OAuthClient(config=_make_oauth_config(), state_store=store)
        await client.exchange_code(code="auth-code-123", state="pending-state")
        body = parse_qs(httpx_mock.get_request().content.decode())
        assert body["redirect_uri"] == ["https://app.example.com/callback"]
        assert body["code_verifier"] == ["stored-verifier"]

    async def test_exchange_state_not_matching_pending_state_raises(self, httpx_mock: HTTPXMock) -> None:
        client = OAuthClient(config=_make_config())
        with pytest.raises(StateError):
            await client.exchange_code(code="auth-code-123", state="forged-state", pending_state=_pending_state())
        assert httpx_mock.get_requests() == []

    @pytest.mark.parametrize("state", ["pénding-state", "pending-state\ud800"], ids=["non-ascii", "lone-surrogate"])
    async def test_exchange_unicode_state_mismatch_raises_state_error(self, httpx_mock: HTTPXMock, state: str) -> None:
        client = OAuthClient(config=_make_config())
        with pytest.raises(StateError):
            await client.exchange_code(code="auth-code-123", state=state, pending_state=_pending_state())
        assert httpx_mock.get_requests() == []

    async def test_exchange_with_pending_state_and_a_state_store_raises(self, httpx_mock: HTTPXMock) -> None:
        store = AsyncMock()
        store.consume = AsyncMock()
        client = OAuthClient(config=_make_config(), state_store=store)
        with pytest.raises(ConfigurationError):
            await client.exchange_code(code="auth-code-123", state="pending-state", pending_state=_pending_state())
        store.consume.assert_not_awaited()
        assert httpx_mock.get_requests() == []

    async def test_exchange_refuses_a_stored_pending_state_for_another_state(self, httpx_mock: HTTPXMock) -> None:
        store = AsyncMock()
        store.consume = AsyncMock(return_value=_pending_state(state="other-state"))
        client = OAuthClient(config=_make_config(), state_store=store)
        with pytest.raises(StateError):
            await client.exchange_code(code="auth-code-123", state="pending-state")
        assert httpx_mock.get_requests() == []

    @pytest.mark.parametrize("state", [None, ""], ids=["absent", "empty"])
    async def test_exchange_callback_without_state_raises_state_error(
        self, httpx_mock: HTTPXMock, state: str | None
    ) -> None:
        client = OAuthClient(config=_make_config())
        with pytest.raises(StateError):
            await client.exchange_code(code="auth-code-123", state=state, pending_state=_pending_state())  # type: ignore[arg-type]
        assert httpx_mock.get_requests() == []

    @pytest.mark.parametrize("state", [None, ""], ids=["absent", "empty"])
    async def test_exchange_callback_without_state_does_not_touch_the_store(
        self, httpx_mock: HTTPXMock, state: str | None
    ) -> None:
        store = AsyncMock()
        store.consume = AsyncMock()
        client = OAuthClient(config=_make_config(), state_store=store)
        with pytest.raises(StateError):
            await client.exchange_code(code="auth-code-123", state=state)  # type: ignore[arg-type]
        store.consume.assert_not_awaited()
        assert httpx_mock.get_requests() == []

    async def test_exchange_state_without_state_store_raises(self, httpx_mock: HTTPXMock) -> None:
        client = OAuthClient(config=_make_config())
        with pytest.raises(ConfigurationError):
            await client.exchange_code(code="auth-code-123", state="pending-state")
        assert httpx_mock.get_requests() == []

    async def test_exchange_no_key_collision(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "access-abc",
                "token_type": "Bearer",
                "user_id": "provider-U",
            },
        )
        pending = OAuthPendingState(
            state="stored-state",
            redirect_uri="https://app.example.com/callback",
            created_at=time.time(),
            metadata={"user_id": "caller-U"},
        )
        store = AsyncMock()
        store.consume = AsyncMock(return_value=pending)
        config = _make_oauth_config()
        client = OAuthClient(config=config, state_store=store)
        tokens = await client.exchange_code(code="auth-code-123", state="stored-state")
        assert tokens.metadata["user_id"] == "provider-U"
        assert tokens.context["user_id"] == "caller-U"

    async def test_exchange_state_not_found_raises(self):
        store = AsyncMock()
        store.consume = AsyncMock(return_value=None)
        config = _make_config()
        client = OAuthClient(config=config, state_store=store)
        with pytest.raises(StateError):
            await client.exchange_code(code="auth-code-123", state="bad-state")

    async def test_exchange_token_endpoint_error(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "invalid_grant", "error_description": "Code expired"},
        )
        config = _make_oauth_config()
        client = OAuthClient(config=config)
        with pytest.raises(TokenExchangeError):
            await client.exchange_code(
                code="bad-code",
                state="pending-state",
                pending_state=_pending_state(),
            )

    async def test_exchange_error_exposes_error_code(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "invalid_grant", "error_description": "Code expired"},
        )
        client = OAuthClient(config=_make_oauth_config())
        with pytest.raises(TokenExchangeError) as exc_info:
            await client.exchange_code(
                code="bad-code",
                state="pending-state",
                pending_state=_pending_state(),
            )
        assert exc_info.value.error_code == "invalid_grant"

    async def test_exchange_string_error_description_rendered_in_message(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "invalid_grant", "error_description": "Code expired"},
        )
        client = OAuthClient(config=_make_oauth_config())
        with pytest.raises(TokenExchangeError) as exc_info:
            await client.exchange_code(
                code="bad-code",
                state="pending-state",
                pending_state=_pending_state(),
            )
        assert str(exc_info.value) == "invalid_grant: Code expired"

    async def test_exchange_non_string_error_description_omitted_from_message(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={
                "error": "invalid_grant",
                "error_description": {"nested": "obj", "leak": "SECRET-ISH-DATA"},
            },
        )
        client = OAuthClient(config=_make_oauth_config())
        with pytest.raises(TokenExchangeError) as exc_info:
            await client.exchange_code(
                code="bad-code",
                state="pending-state",
                pending_state=_pending_state(),
            )
        assert exc_info.value.error_code == "invalid_grant"
        assert str(exc_info.value) == "invalid_grant"
        assert "SECRET-ISH-DATA" not in str(exc_info.value)

    async def test_exchange_extra_fields_in_token_set(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "access-abc",
                "token_type": "Bearer",
                "team_id": "T123",
                "authed_user": {"id": "U456"},
            },
        )
        config = _make_oauth_config()
        client = OAuthClient(config=config)
        tokens = await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        assert tokens.metadata["team_id"] == "T123"
        assert tokens.metadata["authed_user"] == {"id": "U456"}

    async def test_exchange_client_secret_post(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config(token_endpoint_auth_method="client_secret_post")
        client = OAuthClient(config=config)
        await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        request = httpx_mock.get_request()
        assert b"client_id=test-client" in request.content
        assert b"client_secret=test-secret" in request.content

    async def test_exchange_client_secret_basic(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config(token_endpoint_auth_method="client_secret_basic")
        client = OAuthClient(config=config)
        await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        request = httpx_mock.get_request()
        assert request.headers.get("authorization", "").startswith("Basic ")

    async def test_exchange_public_client_no_secret(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config(client_secret=None, token_endpoint_auth_method="none")
        client = OAuthClient(config=config)
        tokens = await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        assert tokens.access_token == "access-abc"
        request = httpx_mock.get_request()
        assert b"client_id=test-client" in request.content
        assert b"client_secret" not in request.content

    @pytest.mark.parametrize(
        ("secret", "auth_method", "expect_secret_sent"),
        [
            (SecretStr("test-secret"), "client_secret_post", True),
            (None, "none", False),
        ],
    )
    async def test_token_body_includes_secret_only_when_present(
        self, httpx_mock, secret, auth_method, expect_secret_sent
    ):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config(client_secret=secret, token_endpoint_auth_method=auth_method)
        client = OAuthClient(config=config)
        await client.exchange_code(code="code", state="pending-state", pending_state=_pending_state())
        request = httpx_mock.get_request()
        assert (b"client_secret=" in request.content) is expect_secret_sent

    async def test_token_request_uses_transport_factory(self):
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            del request
            return httpx.Response(200, json={"access_token": "access-abc", "token_type": "Bearer"})

        def factory(url: str) -> httpx.MockTransport:
            calls.append(url)
            return httpx.MockTransport(handler)

        config = _make_oauth_config()
        client = OAuthClient(config=config, transport_factory=factory)
        tokens = await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        assert tokens.access_token == "access-abc"
        assert calls == ["https://provider.example.com/token"]

    async def test_exchange_matching_iss_succeeds(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config(issuer="https://provider.example.com")
        client = OAuthClient(config=config)
        tokens = await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
            iss="https://provider.example.com",
        )
        assert tokens.access_token == "access-abc"

    async def test_exchange_mismatched_iss_rejected_before_token_request(self, httpx_mock: HTTPXMock) -> None:
        config = _make_config(issuer="https://provider.example.com")
        client = OAuthClient(config=config)
        with pytest.raises(IssuerValidationError):
            await client.exchange_code(
                code="auth-code-123",
                state="pending-state",
                pending_state=_pending_state(),
                iss="https://attacker.example.com",
            )
        assert httpx_mock.get_requests() == []

    async def test_exchange_missing_iss_rejected_when_required(self, httpx_mock: HTTPXMock) -> None:
        config = _make_config(issuer="https://provider.example.com", require_iss=True)
        client = OAuthClient(config=config)
        with pytest.raises(IssuerValidationError):
            await client.exchange_code(
                code="auth-code-123",
                state="pending-state",
                pending_state=_pending_state(),
            )
        assert httpx_mock.get_requests() == []

    async def test_exchange_missing_iss_allowed_when_not_required(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config(issuer="https://provider.example.com", require_iss=False)
        client = OAuthClient(config=config)
        tokens = await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
        )
        assert tokens.access_token == "access-abc"

    async def test_exchange_without_configured_issuer_ignores_iss(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer"},
        )
        config = _make_oauth_config()
        client = OAuthClient(config=config)
        tokens = await client.exchange_code(
            code="auth-code-123",
            state="pending-state",
            pending_state=_pending_state(),
            iss="https://anything.example.com",
        )
        assert tokens.access_token == "access-abc"

    async def test_exchange_bad_iss_does_not_consume_state(self) -> None:
        store = AsyncMock()
        store.consume = AsyncMock()
        config = _make_config(issuer="https://provider.example.com")
        client = OAuthClient(config=config, state_store=store)
        with pytest.raises(IssuerValidationError):
            await client.exchange_code(
                code="auth-code-123",
                state="stored-state",
                iss="https://attacker.example.com",
            )
        store.consume.assert_not_awaited()


class TestExchangeCodeNonce:
    async def _exchange(
        self,
        httpx_mock: HTTPXMock,
        response: dict[str, object],
        nonce: str | None = "sent-nonce",
        scopes: tuple[str, ...] = ("openid", "email"),
    ) -> TokenSet:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer", **response},
            is_optional=True,
        )
        client = OAuthClient(config=_make_config(scopes=list(scopes)))
        return await client.exchange_code(
            code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce=nonce)
        )

    async def test_matching_nonce_is_accepted(self, httpx_mock: HTTPXMock) -> None:
        tokens = await self._exchange(httpx_mock, {"id_token": _id_token(_openid_claims(nonce="sent-nonce"))})
        assert tokens.access_token == "access-abc"

    @pytest.mark.parametrize("response", [{}, {"id_token": None}], ids=["absent", "null"])
    async def test_response_without_id_token_is_refused_when_a_nonce_was_sent(
        self, httpx_mock: HTTPXMock, response: dict[str, object]
    ) -> None:
        with pytest.raises(NonceValidationError, match="^Token response carries no ID token for the OpenID request$"):
            await self._exchange(httpx_mock, response)

    async def test_nonce_is_not_checked_without_the_openid_scope(self, httpx_mock: HTTPXMock) -> None:
        """A request that sent no nonce accepts an ID token without one, but its other claims are still checked."""
        tokens = await self._exchange(
            httpx_mock, {"id_token": _id_token(_openid_claims())}, nonce=None, scopes=("email",)
        )
        assert tokens.access_token == "access-abc"

    @pytest.mark.parametrize(
        "id_token",
        ["not-a-token", _id_token(_openid_claims(aud="other-client"))],
        ids=["unreadable", "other audience"],
    )
    async def test_id_token_claims_are_checked_without_the_openid_scope(
        self, httpx_mock: HTTPXMock, id_token: str
    ) -> None:
        with pytest.raises(IdTokenValidationError) as exc_info:
            await self._exchange(httpx_mock, {"id_token": id_token}, nonce=None, scopes=("email",))
        assert not isinstance(exc_info.value, NonceValidationError)

    async def test_openid_pending_state_without_a_nonce_is_refused(self, httpx_mock: HTTPXMock) -> None:
        id_token = _id_token(_openid_claims(nonce="sent-nonce"))
        with pytest.raises(NonceValidationError, match="pending state has no nonce"):
            await self._exchange(httpx_mock, {"id_token": id_token}, nonce=None)
        assert httpx_mock.get_requests() == []

    async def test_openid_pending_state_with_an_empty_nonce_is_refused(self, httpx_mock: HTTPXMock) -> None:
        id_token = _id_token(_openid_claims(nonce=""))
        with pytest.raises(NonceValidationError, match="pending state has no nonce"):
            await self._exchange(httpx_mock, {"id_token": id_token}, nonce="")
        assert httpx_mock.get_requests() == []

    @pytest.mark.parametrize("response", [{}, {"id_token": None}], ids=["absent", "null"])
    async def test_openid_pending_state_without_a_nonce_is_refused_without_an_id_token(
        self, httpx_mock: HTTPXMock, response: dict[str, object]
    ) -> None:
        with pytest.raises(NonceValidationError, match="pending state has no nonce"):
            await self._exchange(httpx_mock, response, nonce=None)
        assert httpx_mock.get_requests() == []

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"nonce": "other-nonce"}, "ID token nonce does not match"),
            ({"nonce": "sént-nonce"}, "ID token nonce does not match"),
            ({"nonce": ["sent-nonce"]}, "ID token nonce does not match"),
            ({}, "ID token carries no nonce"),
        ],
        ids=["mismatch", "non-ascii", "not-a-string", "missing"],
    )
    async def test_id_token_without_the_sent_nonce_is_refused(
        self, httpx_mock: HTTPXMock, overrides: dict[str, object], message: str
    ) -> None:
        # The token is built when the test runs, so its expiry is measured from now and not from collection.
        id_token = _id_token(_openid_claims(**overrides))
        with pytest.raises(NonceValidationError, match=message) as exc_info:
            await self._exchange(httpx_mock, {"id_token": id_token})
        assert isinstance(exc_info.value, TokenExchangeError)

    @pytest.mark.parametrize(
        "id_token", [_id_token(["sent-nonce"]), "not-a-token"], ids=["claims-not-object", "not-compact"]
    )
    async def test_unreadable_id_token_is_refused(self, httpx_mock: HTTPXMock, id_token: object) -> None:
        """A token that cannot be read fails as an ID token, not as a nonce mismatch."""
        with pytest.raises(IdTokenValidationError, match="ID token could not be read") as exc_info:
            await self._exchange(httpx_mock, {"id_token": id_token})
        assert not isinstance(exc_info.value, NonceValidationError)

    async def test_unreadable_id_token_error_has_no_cause(self, httpx_mock: HTTPXMock) -> None:
        with pytest.raises(IdTokenValidationError) as exc_info:
            await self._exchange(httpx_mock, {"id_token": "not-a-token"})
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    @pytest.mark.parametrize("id_token", ["", 42, False, {}], ids=["empty", "number", "false", "object"])
    async def test_id_token_that_is_not_a_compact_token_is_refused(
        self, httpx_mock: HTTPXMock, id_token: object
    ) -> None:
        with pytest.raises(IdTokenValidationError, match="ID token could not be read"):
            await self._exchange(httpx_mock, {"id_token": id_token})

    async def test_sent_nonce_is_checked_after_the_scopes_change(self, httpx_mock: HTTPXMock) -> None:
        id_token = _id_token(_openid_claims(nonce="other-nonce"))
        with pytest.raises(NonceValidationError, match="ID token nonce does not match"):
            await self._exchange(httpx_mock, {"id_token": id_token}, scopes=("email",))

    @pytest.mark.parametrize(
        "overrides",
        [
            {"scopes": [], "extra_params": {"scope": "openid email"}},
            {"scopes": [], "authorize_url": "https://provider.example.com/authorize?scope=openid"},
        ],
        ids=["extra-params", "authorize-url-query"],
    )
    async def test_openid_scope_from_any_source_needs_a_nonce(
        self, httpx_mock: HTTPXMock, overrides: dict[str, object]
    ) -> None:
        httpx_mock.add_response(
            is_optional=True,
            url="https://provider.example.com/token",
            json={
                "access_token": "access-abc",
                "token_type": "Bearer",
                "id_token": _id_token(_openid_claims(nonce="x")),
            },
        )
        client = OAuthClient(config=_make_config(**overrides))
        with pytest.raises(NonceValidationError, match="pending state has no nonce"):
            await client.exchange_code(code="auth-code-123", state="pending-state", pending_state=_pending_state())
        assert httpx_mock.get_requests() == []

    async def test_stored_matching_nonce_is_accepted(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "access-abc",
                "token_type": "Bearer",
                "id_token": _id_token(_openid_claims(nonce="sent-nonce")),
            },
        )
        store = AsyncMock()
        store.consume = AsyncMock(return_value=_pending_state(nonce="sent-nonce"))
        client = OAuthClient(config=_make_config(), state_store=store)
        tokens = await client.exchange_code(code="auth-code-123", state="pending-state")
        assert tokens.access_token == "access-abc"

    async def test_stored_nonce_is_checked(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "access-abc",
                "token_type": "Bearer",
                "id_token": _id_token(_openid_claims(nonce="other")),
            },
        )
        store = AsyncMock()
        store.consume = AsyncMock(return_value=_pending_state(nonce="sent-nonce"))
        client = OAuthClient(config=_make_config(), state_store=store)
        with pytest.raises(NonceValidationError):
            await client.exchange_code(code="auth-code-123", state="pending-state")

    async def test_stored_openid_pending_state_without_a_nonce_is_refused(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            is_optional=True,
            url="https://provider.example.com/token",
            json={
                "access_token": "access-abc",
                "token_type": "Bearer",
                "id_token": _id_token(_openid_claims(nonce="x")),
            },
        )
        store = AsyncMock()
        store.consume = AsyncMock(return_value=_pending_state(nonce=None))
        client = OAuthClient(config=_make_config(), state_store=store)
        with pytest.raises(NonceValidationError, match="pending state has no nonce"):
            await client.exchange_code(code="auth-code-123", state="pending-state")
        assert httpx_mock.get_requests() == []

    async def test_refresh_checks_no_nonce(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-new", "token_type": "Bearer", "id_token": _id_token(_openid_claims())},
        )
        tokens = await OAuthClient(config=_make_config()).refresh_token("refresh-xyz")
        assert tokens.access_token == "access-new"


class TestExchangeCodeIdTokenClaims:
    async def _exchange(self, httpx_mock: HTTPXMock, claims: object, issuer: str | None = None) -> TokenSet:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer", "id_token": _id_token(claims)},
        )
        client = OAuthClient(config=_make_config(issuer=issuer))
        return await client.exchange_code(
            code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
        )

    @staticmethod
    def _claims(extra: dict[str, object]) -> dict[str, object]:
        """Return claims for the sent nonce with ``extra`` on top, computing a relative expiry at call time."""
        claims = dict(extra)
        offset = claims.pop("exp_offset", None)
        if isinstance(offset, int | float):
            claims["exp"] = time.time() + offset
        return _openid_claims(nonce="sent-nonce", **claims)

    @pytest.mark.parametrize(
        "extra",
        [
            {},
            {"aud": ["test-client"]},
            {"aud": ["test-client", "test-client"]},
            {"aud": ["test-client", "other-client"], "azp": "test-client"},
            {"azp": "test-client"},
            {"exp_offset": -30},
            {"exp_offset": 300.5},
            {"exp": 10**400},
        ],
        ids=[
            "string audience",
            "single audience list",
            "repeated audience",
            "several audiences with this authorized party",
            "authorized party",
            "expiry within the clock skew",
            "fractional expiry",
            "expiry too large for a float",
        ],
    )
    async def test_a_token_issued_to_this_client_is_accepted(
        self, httpx_mock: HTTPXMock, extra: dict[str, object]
    ) -> None:
        tokens = await self._exchange(httpx_mock, self._claims(extra))
        assert tokens.access_token == "access-abc"

    @pytest.mark.parametrize(
        ("extra", "message"),
        [
            ({"aud": "other-client"}, "audience does not include this client"),
            ({"aud": ["other-client"]}, "audience does not include this client"),
            ({"aud": 42}, "audience is not a name or a list of names"),
            ({"aud": None}, "audience is not a name or a list of names"),
            ({"aud": []}, "names no audience"),
            ({"aud": ["test-client", 42], "azp": "test-client"}, "audience is not a name or a list of names"),
            ({"aud": ["test-client", {}], "azp": "test-client"}, "audience is not a name or a list of names"),
            ({"aud": [[]]}, "audience is not a name or a list of names"),
            ({"aud": ["test-client", "other-client"]}, "several audiences without an authorized party"),
            ({"aud": ["test-client", "other"], "azp": "other"}, "authorized party is not this client"),
            ({"azp": "other-client"}, "authorized party is not this client"),
            ({"exp_offset": -120}, "has expired"),
            ({"exp": None}, "expired or carries no usable expiry"),
            ({"exp": "later"}, "expired or carries no usable expiry"),
            ({"exp": True}, "expired or carries no usable expiry"),
            ({"exp": float("nan")}, "expired or carries no usable expiry"),
            ({"exp": float("inf")}, "expired or carries no usable expiry"),
        ],
        ids=[
            "other audience",
            "other audience list",
            "audience not a name",
            "no audience",
            "empty audience list",
            "audience list with a member that is not a name",
            "audience list with an object member",
            "audience list with a list member",
            "several audiences without an authorized party",
            "other authorized party among several audiences",
            "other authorized party",
            "expired",
            "no expiry",
            "expiry not a number",
            "expiry a boolean",
            "expiry not a finite number",
            "expiry infinite",
        ],
    )
    async def test_a_token_not_issued_to_this_client_is_refused(
        self, httpx_mock: HTTPXMock, extra: dict[str, object], message: str
    ) -> None:
        with pytest.raises(IdTokenValidationError, match=message):
            await self._exchange(httpx_mock, self._claims(extra))

    async def test_the_issuer_is_checked_when_the_config_names_one(self, httpx_mock: HTTPXMock) -> None:
        claims = _openid_claims(nonce="sent-nonce", iss="https://issuer.example.com")
        tokens = await self._exchange(httpx_mock, claims, issuer="https://issuer.example.com")
        assert tokens.access_token == "access-abc"

    @pytest.mark.parametrize(
        "claims",
        [
            _openid_claims(nonce="sent-nonce", iss="https://other.example.com"),
            _openid_claims(nonce="sent-nonce", iss="https://issuer.example.com/"),
            _openid_claims(nonce="sent-nonce"),
        ],
        ids=["other issuer", "issuer with a terminating slash", "no issuer"],
    )
    async def test_another_issuer_is_refused_when_the_config_names_one(
        self, httpx_mock: HTTPXMock, claims: object
    ) -> None:
        with pytest.raises(IdTokenValidationError, match="issuer does not match"):
            await self._exchange(httpx_mock, claims, issuer="https://issuer.example.com")

    async def test_the_issuer_is_not_checked_when_the_config_names_none(self, httpx_mock: HTTPXMock) -> None:
        tokens = await self._exchange(httpx_mock, _openid_claims(nonce="sent-nonce", iss="https://any.example.com"))
        assert tokens.access_token == "access-abc"

    async def test_the_audience_is_checked_before_the_nonce(self, httpx_mock: HTTPXMock) -> None:
        """A token for another client is refused as such, even when its nonce is wrong too."""
        with pytest.raises(IdTokenValidationError, match="audience") as excinfo:
            await self._exchange(httpx_mock, _openid_claims(nonce="other-nonce", aud="other-client"))
        assert not isinstance(excinfo.value, NonceValidationError)


class TestExchangeCodeNonceRevocation:
    REVOKE_URL = "https://provider.example.com/revoke"

    async def _refused(
        self,
        httpx_mock: HTTPXMock,
        response: dict[str, object],
        revocation_url: str | None = REVOKE_URL,
    ) -> IdTokenValidationError:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "token_type": "Bearer", **response},
        )
        client = OAuthClient(config=_make_config(revocation_url=revocation_url))
        with pytest.raises(IdTokenValidationError) as exc_info:
            await client.exchange_code(
                code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
            )
        return exc_info.value

    def _revoked(self, httpx_mock: HTTPXMock) -> list[str]:
        return [
            parse_qs(request.content.decode())["token"][0] for request in httpx_mock.get_requests(url=self.REVOKE_URL)
        ]

    async def test_a_mismatched_nonce_revokes_both_tokens(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=self.REVOKE_URL, is_reusable=True)

        await self._refused(
            httpx_mock, {"refresh_token": "refresh-xyz", "id_token": _id_token(_openid_claims(nonce="other"))}
        )

        assert sorted(self._revoked(httpx_mock)) == ["access-abc", "refresh-xyz"]

    async def test_a_malformed_audience_revokes_both_tokens(self, httpx_mock: HTTPXMock) -> None:
        """A member that cannot be hashed must still be refused as an ID token failure, so revocation runs."""
        httpx_mock.add_response(url=self.REVOKE_URL, is_reusable=True)
        id_token = _id_token(_openid_claims(nonce="sent-nonce", aud=["test-client", {}]))

        await self._refused(httpx_mock, {"refresh_token": "refresh-xyz", "id_token": id_token})

        assert sorted(self._revoked(httpx_mock)) == ["access-abc", "refresh-xyz"]

    async def test_a_token_for_another_client_revokes_both_tokens(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=self.REVOKE_URL, is_reusable=True)
        id_token = _id_token(_openid_claims(nonce="sent-nonce", aud="other-client"))

        error = await self._refused(httpx_mock, {"refresh_token": "refresh-xyz", "id_token": id_token})

        assert not isinstance(error, NonceValidationError)
        assert sorted(self._revoked(httpx_mock)) == ["access-abc", "refresh-xyz"]

    async def test_a_response_without_an_id_token_revokes_the_access_token(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=self.REVOKE_URL)

        await self._refused(httpx_mock, {})

        assert self._revoked(httpx_mock) == ["access-abc"]

    async def test_a_revocation_failure_still_raises_the_nonce_error(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        httpx_mock.add_response(url=self.REVOKE_URL, status_code=503, is_reusable=True)

        error = await self._refused(httpx_mock, {"refresh_token": "refresh-xyz"})

        assert str(error) == "Token response carries no ID token for the OpenID request"
        assert "refresh-xyz" not in caplog.text
        assert "access-abc" not in caplog.text
        assert "could not be revoked" in caplog.text

    async def test_a_transport_failure_while_revoking_still_raises_the_nonce_error(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        httpx_mock.add_exception(httpx.ConnectError("refused"), url=self.REVOKE_URL)

        error = await self._refused(httpx_mock, {})

        assert isinstance(error, NonceValidationError)
        assert error.__context__ is None
        assert "could not be revoked" in caplog.text

    async def test_a_provider_without_revocation_logs_that_the_tokens_stay_valid(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        await self._refused(httpx_mock, {}, revocation_url=None)

        assert len(httpx_mock.get_requests()) == 1
        assert "stay valid" in caplog.text

    @pytest.mark.parametrize(
        "failure_type", [ConfigurationError, RevocationError, RuntimeError], ids=["library", "revocation", "unexpected"]
    )
    async def test_a_handler_failure_that_repeats_the_token_keeps_it_out_of_the_log(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture, failure_type: type[Exception]
    ) -> None:
        class FailingHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                raise failure_type(f"provider refused token {token}")

        httpx_mock.add_response(url="https://provider.example.com/token", json={"access_token": "access-abc"})
        client = OAuthClient(config=_make_config(revocation_url=self.REVOKE_URL), revocation_handler=FailingHandler())

        with pytest.raises(NonceValidationError):
            await client.exchange_code(
                code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
            )

        assert "could not be revoked" in caplog.text
        assert "access-abc" not in caplog.text
        assert "provider refused" not in caplog.text

    async def test_a_cancelled_revocation_still_raises_the_nonce_error(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        class CancelledHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                raise asyncio.CancelledError

        httpx_mock.add_response(url="https://provider.example.com/token", json={"access_token": "access-abc"})
        client = OAuthClient(config=_make_config(revocation_url=self.REVOKE_URL), revocation_handler=CancelledHandler())

        with pytest.raises(NonceValidationError):
            await client.exchange_code(
                code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
            )

        assert "(interrupted)" in caplog.text

    async def test_a_revocation_that_never_returns_stops_at_the_time_limit(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("apron_auth.client._REFUSED_TOKEN_REVOCATION_TIMEOUT_SECONDS", 0.05)

        class SlowRefreshHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                if token == "refresh-xyz":
                    await asyncio.Event().wait()
                return True

        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "refresh_token": "refresh-xyz"},
        )
        client = OAuthClient(
            config=_make_config(revocation_url=self.REVOKE_URL), revocation_handler=SlowRefreshHandler()
        )

        with pytest.raises(NonceValidationError):
            await asyncio.wait_for(
                client.exchange_code(
                    code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
                ),
                timeout=5,
            )

        assert [record.getMessage() for record in caplog.records if record.name == "apron_auth.client"] == [
            "revoking the refresh token of a refused token response at provider.example.com "
            "did not finish within the time limit"
        ]

    async def test_each_unfinished_revocation_is_logged_with_its_own_reason(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("apron_auth.client._REFUSED_TOKEN_REVOCATION_TIMEOUT_SECONDS", 0.05)

        class MixedHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                if token == "access-abc":
                    raise asyncio.CancelledError
                await asyncio.Event().wait()
                return True

        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "refresh_token": "refresh-xyz"},
        )
        client = OAuthClient(config=_make_config(revocation_url=self.REVOKE_URL), revocation_handler=MixedHandler())

        with pytest.raises(NonceValidationError):
            await asyncio.wait_for(
                client.exchange_code(
                    code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
                ),
                timeout=5,
            )

        assert sorted(record.getMessage() for record in caplog.records if record.name == "apron_auth.client") == [
            "revoking the refresh token of a refused token response at provider.example.com "
            "did not finish within the time limit",
            "the access token of a refused token response could not be revoked at provider.example.com (interrupted)",
        ]

    @pytest.mark.parametrize("ending", ["returns", "raises"])
    async def test_a_revocation_that_ends_after_the_limit_is_logged_as_timed_out(
        self,
        httpx_mock: HTTPXMock,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
        ending: str,
    ) -> None:
        monkeypatch.setattr("apron_auth.client._REFUSED_TOKEN_REVOCATION_TIMEOUT_SECONDS", 0.05)

        class HandlerAbortError(BaseException):
            pass

        class SwallowingHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    if ending == "raises":
                        raise HandlerAbortError from None
                return True

        httpx_mock.add_response(url="https://provider.example.com/token", json={"access_token": "access-abc"})
        client = OAuthClient(
            config=_make_config(revocation_url=self.REVOKE_URL), revocation_handler=SwallowingHandler()
        )

        with pytest.raises(NonceValidationError):
            await asyncio.wait_for(
                client.exchange_code(
                    code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
                ),
                timeout=5,
            )

        assert [record.getMessage() for record in caplog.records if record.name == "apron_auth.client"] == [
            "revoking the access token of a refused token response at provider.example.com "
            "did not finish within the time limit"
        ]

    async def test_every_outcome_is_logged_before_a_handler_abort_is_raised(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("apron_auth.client._REFUSED_TOKEN_REVOCATION_TIMEOUT_SECONDS", 0.05)

        class HandlerAbortError(BaseException):
            pass

        class AbortingHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                if token == "refresh-xyz":
                    raise HandlerAbortError
                await asyncio.Event().wait()
                return True

        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "refresh_token": "refresh-xyz"},
        )
        client = OAuthClient(config=_make_config(revocation_url=self.REVOKE_URL), revocation_handler=AbortingHandler())

        with pytest.raises(HandlerAbortError):
            await asyncio.wait_for(
                client.exchange_code(
                    code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
                ),
                timeout=5,
            )

        assert [record.getMessage() for record in caplog.records if record.name == "apron_auth.client"] == [
            "revoking the access token of a refused token response at provider.example.com "
            "did not finish within the time limit"
        ]

    async def test_a_canceled_caller_cancels_the_revocations(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        started = asyncio.Event()
        canceled: list[str] = []

        class HangingHandler:
            async def revoke(self, token: str, config: ProviderConfig) -> bool:
                started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    canceled.append(token)
                    raise
                return True

        httpx_mock.add_response(url="https://provider.example.com/token", json={"access_token": "access-abc"})
        client = OAuthClient(config=_make_config(revocation_url=self.REVOKE_URL), revocation_handler=HangingHandler())
        exchange = asyncio.create_task(
            client.exchange_code(
                code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
            )
        )
        await asyncio.wait_for(started.wait(), timeout=5)

        exchange.cancel()

        with pytest.raises(asyncio.CancelledError):
            await exchange
        assert canceled == ["access-abc"]
        assert [record for record in caplog.records if record.name == "apron_auth.client"] == []

    async def test_a_pending_state_without_a_nonce_redeems_no_code(self, httpx_mock: HTTPXMock) -> None:
        client = OAuthClient(config=_make_config(scopes=["openid"], revocation_url=self.REVOKE_URL))

        with pytest.raises(NonceValidationError, match="pending state has no nonce"):
            await client.exchange_code(
                code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce=None)
            )

        assert httpx_mock.get_requests() == []

    async def test_a_refused_response_without_tokens_logs_nothing(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        httpx_mock.add_response(url="https://provider.example.com/token", json={"token_type": "Bearer"})
        client = OAuthClient(config=_make_config(revocation_url=None))

        with pytest.raises(NonceValidationError):
            await client.exchange_code(
                code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
            )

        assert "stay valid" not in caplog.text

    async def test_a_warning_names_the_revocation_host(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        httpx_mock.add_response(url=self.REVOKE_URL, status_code=503)

        await self._refused(httpx_mock, {})

        assert "provider.example.com" in caplog.text

    async def test_a_verified_response_revokes_nothing(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "access-abc", "id_token": _id_token(_openid_claims(nonce="sent-nonce"))},
        )
        client = OAuthClient(config=_make_config(revocation_url=self.REVOKE_URL))

        await client.exchange_code(
            code="auth-code-123", state="pending-state", pending_state=_pending_state(nonce="sent-nonce")
        )

        assert httpx_mock.get_requests(url=self.REVOKE_URL) == []


class TestRefreshToken:
    async def test_successful_refresh(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={
                "access_token": "new-access",
                "token_type": "Bearer",
                "refresh_token": "new-refresh",
                "expires_in": 3600,
            },
        )
        config = _make_config()
        client = OAuthClient(config=config)
        tokens = await client.refresh_token(refresh_token="old-refresh")
        assert tokens.access_token == "new-access"
        assert tokens.refresh_token == "new-refresh"

    async def test_refresh_sends_correct_grant_type(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "new-access", "token_type": "Bearer"},
        )
        config = _make_config()
        client = OAuthClient(config=config)
        await client.refresh_token(refresh_token="old-refresh")
        request = httpx_mock.get_request()
        assert b"grant_type=refresh_token" in request.content
        assert b"refresh_token=old-refresh" in request.content

    async def test_refresh_includes_resource_when_set(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "new-access", "token_type": "Bearer"},
        )
        config = _make_config(resource="https://mcp.example.com/")
        client = OAuthClient(config=config)
        await client.refresh_token(refresh_token="old-refresh")
        request = httpx_mock.get_request()
        body = parse_qs(request.content.decode())
        assert body["resource"] == ["https://mcp.example.com/"]

    async def test_refresh_omits_resource_when_unset(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            json={"access_token": "new-access", "token_type": "Bearer"},
        )
        config = _make_config()
        client = OAuthClient(config=config)
        await client.refresh_token(refresh_token="old-refresh")
        request = httpx_mock.get_request()
        assert b"resource" not in request.content

    @pytest.mark.parametrize(
        ("status", "code"),
        [(400, "invalid_grant"), (401, "unauthorized_client"), (401, "invalid_client"), (400, "invalid_scope")],
    )
    async def test_refresh_rejection_cannot_be_retried(self, httpx_mock, status: int, code: str):
        httpx_mock.add_response(url="https://provider.example.com/token", status_code=status, json={"error": code})
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(TokenRefreshError, match=code) as exc_info:
            await client.refresh_token(refresh_token="bad-refresh")
        assert exc_info.value.kind is FailureKind.REJECTED
        assert exc_info.value.retryable is False

    @pytest.mark.parametrize("code", ["server_error", "temporarily_unavailable"])
    async def test_refresh_server_side_error_code_may_be_retried(self, httpx_mock, code: str):
        httpx_mock.add_response(url="https://provider.example.com/token", status_code=500, json={"error": code})
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.kind is FailureKind.SERVER_ERROR
        assert exc_info.value.retryable is True

    async def test_refresh_server_error_without_a_code_may_be_retried(self, httpx_mock):
        httpx_mock.add_response(url="https://provider.example.com/token", status_code=503, json={})
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.kind is FailureKind.SERVER_ERROR

    async def test_refresh_network_error_may_be_retried(self, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.kind is FailureKind.UNREACHABLE
        assert exc_info.value.retryable is True

    async def test_refresh_timeout_may_be_retried(self, httpx_mock):
        httpx_mock.add_exception(httpx.ReadTimeout("read timed out"))
        config = _make_config()
        client = OAuthClient(config=config)
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.kind is FailureKind.TIMEOUT

    async def test_refresh_custom_retryable_error_code(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "try_later", "error_description": "Busy"},
        )
        config = _make_config()
        client = OAuthClient(config=config, retryable_error_codes={"try_later"})
        with pytest.raises(TokenRefreshError, match="try_later") as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.retryable is True

    async def test_refresh_custom_codes_preserve_defaults(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token", status_code=503, json={"error": "server_error"}
        )
        config = _make_config()
        client = OAuthClient(config=config, retryable_error_codes={"try_later"})
        with pytest.raises(TokenRefreshError, match="server_error") as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.retryable is True

    async def test_exchange_classifies_a_rejection_like_refresh(self, httpx_mock):
        httpx_mock.add_response(
            url="https://provider.example.com/token", status_code=400, json={"error": "invalid_grant"}
        )
        config = _make_config()
        client = OAuthClient(config=config)
        _, pending = await client.get_authorization_url(redirect_uri="https://app.example.com/cb")
        with pytest.raises(TokenExchangeError) as exc_info:
            await client.exchange_code(code="dead-code", state=pending.state, pending_state=pending)
        assert exc_info.value.kind is FailureKind.REJECTED
        assert exc_info.value.error_code == "invalid_grant"
        assert exc_info.value.retryable is False

    async def test_exchange_classifies_an_outage_like_refresh(self, httpx_mock):
        httpx_mock.add_response(url="https://provider.example.com/token", status_code=503, json={})
        config = _make_config()
        client = OAuthClient(config=config)
        _, pending = await client.get_authorization_url(redirect_uri="https://app.example.com/cb")
        with pytest.raises(TokenExchangeError) as exc_info:
            await client.exchange_code(code="some-code", state=pending.state, pending_state=pending)
        assert exc_info.value.kind is FailureKind.SERVER_ERROR
        assert exc_info.value.retryable is True

    async def test_refresh_invalid_grant_exposes_error_code(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "invalid_grant", "error_description": "Token revoked"},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="revoked-refresh")
        assert exc_info.value.error_code == "invalid_grant"

    async def test_refresh_invalid_client_exposes_error_code(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=401,
            json={"error": "invalid_client"},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="bad-refresh")
        assert exc_info.value.error_code == "invalid_client"

    async def test_refresh_unauthorized_client_exposes_error_code(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "unauthorized_client"},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="bad-refresh")
        assert exc_info.value.error_code == "unauthorized_client"

    async def test_refresh_transient_error_exposes_error_code(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=500,
            json={"error": "server_error"},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == "server_error"

    async def test_refresh_network_error_has_empty_error_code(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == ""

    async def test_refresh_server_error_without_body_has_empty_error_code(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=503,
            text="Service Unavailable",
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == ""

    @pytest.mark.parametrize(
        "content",
        [b'["maintenance"]', b"[" * 100_000 + b"]" * 100_000],
        ids=["not an object", "deeply nested"],
    )
    async def test_refresh_server_error_with_unusable_body_keeps_status_prefix(
        self, httpx_mock: HTTPXMock, content: bytes
    ) -> None:
        """A failure body that holds no error object leaves the status as the whole message."""
        httpx_mock.add_response(url="https://provider.example.com/token", status_code=503, content=content)
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == ""
        assert str(exc_info.value) == "HTTP 503"

    @pytest.mark.parametrize(
        "content",
        [b"not json", b"[" * 100_000 + b"]" * 100_000],
        ids=["not JSON", "deeply nested"],
    )
    async def test_refresh_unreadable_success_body_is_reported(self, httpx_mock: HTTPXMock, content: bytes) -> None:
        """A success body that cannot be decoded is reported as unreadable, with no chain to the decoder."""
        httpx_mock.add_response(url="https://provider.example.com/token", status_code=200, content=content)
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert str(exc_info.value) == "token response could not be read"
        endpoint_error = exc_info.value.__cause__
        assert endpoint_error is not None
        assert endpoint_error.__cause__ is None
        assert endpoint_error.__context__ is None

    async def test_refresh_non_string_error_value_has_empty_error_code(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=500,
            json={"error": []},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == ""

    async def test_refresh_non_string_error_description_omitted_from_message(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=500,
            json={"error": "server_error", "error_description": {"nested": "obj"}},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == "server_error"
        assert str(exc_info.value) == "server_error"

    async def test_refresh_error_description_without_error_code_keeps_status_prefix(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=500,
            json={"error_description": "backend unavailable"},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == ""
        assert str(exc_info.value) == "HTTP 500: backend unavailable"

    async def test_refresh_permanent_error_non_string_description_omitted_from_message(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={
                "error": "invalid_grant",
                "error_description": {"nested": "obj", "leak": "SECRET-ISH-DATA"},
            },
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="revoked-refresh")
        assert exc_info.value.error_code == "invalid_grant"
        assert str(exc_info.value) == "invalid_grant"
        assert "SECRET-ISH-DATA" not in str(exc_info.value)

    async def test_refresh_non_string_error_in_oauth_error_body_has_empty_error_code(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": {"code": "invalid_grant", "leak": "SECRET-ISH-DATA"}},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == ""
        assert "SECRET-ISH-DATA" not in str(exc_info.value)
        assert str(exc_info.value) == "unspecified token endpoint error"

    async def test_refresh_empty_error_code_keeps_a_descriptive_message(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": ""},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == ""
        assert str(exc_info.value) == "unspecified token endpoint error"

    async def test_refresh_empty_error_code_with_description_keeps_a_descriptive_prefix(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url="https://provider.example.com/token",
            status_code=400,
            json={"error": "", "error_description": "authorization code expired"},
        )
        client = OAuthClient(config=_make_config())
        with pytest.raises(TokenRefreshError) as exc_info:
            await client.refresh_token(refresh_token="some-refresh")
        assert exc_info.value.error_code == ""
        assert str(exc_info.value) == "unspecified token endpoint error: authorization code expired"


class TestRevokeToken:
    async def test_successful_revocation(self, httpx_mock):
        from apron_auth.protocols import StandardRevocationHandler

        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=200)
        config = _make_config(revocation_url="https://provider.example.com/revoke")
        handler = StandardRevocationHandler()
        client = OAuthClient(config=config, revocation_handler=handler)
        result = await client.revoke_token(token="access-token")
        assert result is True

    async def test_revocation_no_url_raises(self):
        config = _make_config(revocation_url=None)
        client = OAuthClient(config=config)
        with pytest.raises(ConfigurationError, match="revocation_url"):
            await client.revoke_token(token="access-token")

    async def test_revocation_with_default_handler(self, httpx_mock):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=200)
        config = _make_config(revocation_url="https://provider.example.com/revoke")
        client = OAuthClient(config=config)
        result = await client.revoke_token(token="access-token")
        assert result is True

    async def test_revocation_default_handler_uses_transport_factory(self):
        """revoke_token's fallback handler routes through the client's transport_factory.

        Closes the SSRF seam gap: the revocation URL is server-supplied, so the
        default handler must honor the same transport_factory as the token request.
        """
        calls: list[str] = []

        def responder(request: httpx.Request) -> httpx.Response:
            del request
            return httpx.Response(200)

        def factory(url: str) -> httpx.MockTransport:
            calls.append(url)
            return httpx.MockTransport(responder)

        config = _make_config(revocation_url="https://provider.example.com/revoke")
        client = OAuthClient(config=config, transport_factory=factory)
        result = await client.revoke_token(token="access-token")
        assert result is True
        assert calls == ["https://provider.example.com/revoke"]

    async def test_revocation_failure_raises(self, httpx_mock):
        httpx_mock.add_response(url="https://provider.example.com/revoke", status_code=503)
        config = _make_config(revocation_url="https://provider.example.com/revoke")
        client = OAuthClient(config=config)
        with pytest.raises(RevocationError):
            await client.revoke_token(token="access-token")

    async def test_revocation_handler_exception_wrapped(self):
        class BrokenHandler:
            async def revoke(self, token: str, config) -> bool:
                msg = "something unexpected"
                raise RuntimeError(msg)

        config = _make_config(revocation_url="https://provider.example.com/revoke")
        client = OAuthClient(config=config, revocation_handler=BrokenHandler())
        with pytest.raises(RevocationError, match="^Failed to revoke token$") as exc_info:
            await client.revoke_token(token="access-token")
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_revocation_error_not_double_wrapped(self):
        class ErrorHandler:
            async def revoke(self, token: str, config) -> bool:
                raise RevocationError("handler error", kind=FailureKind.REJECTED)

        config = _make_config(revocation_url="https://provider.example.com/revoke")
        client = OAuthClient(config=config, revocation_handler=ErrorHandler())
        with pytest.raises(RevocationError, match="handler error") as exc_info:
            await client.revoke_token(token="access-token")
        assert exc_info.value.__cause__ is None


class TestFetchIdentity:
    async def test_google_identity_inferred_from_config(self, httpx_mock):
        httpx_mock.add_response(
            url="https://www.googleapis.com/oauth2/v3/userinfo",
            json={
                "sub": "google-user-123",
                "email": "user@example.com",
                "email_verified": True,
                "name": "Test User",
                "picture": "https://example.com/avatar.png",
            },
        )
        config = _make_config(
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
        )
        client = OAuthClient(config=config)

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity == IdentityProfile(
            provider="google",
            subject="google-user-123",
            email="user@example.com",
            email_verified=True,
            name="Test User",
            avatar_url="https://example.com/avatar.png",
            raw={
                "sub": "google-user-123",
                "email": "user@example.com",
                "email_verified": True,
                "name": "Test User",
                "picture": "https://example.com/avatar.png",
            },
        )

    async def test_github_identity_derives_verified_primary_email(self, httpx_mock):
        httpx_mock.add_response(
            url="https://api.github.com/user",
            json={
                "id": 42,
                "login": "octocat",
                "name": "Octo Cat",
                "email": None,
                "avatar_url": "https://example.com/octo.png",
            },
        )
        httpx_mock.add_response(
            url="https://api.github.com/user/emails",
            json=[
                {"email": "secondary@example.com", "verified": True, "primary": False},
                {"email": "primary@example.com", "verified": True, "primary": True},
            ],
        )
        config = _make_config(
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
        )
        client = OAuthClient(config=config)

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity.provider == "github"
        assert identity.subject == "42"
        assert identity.email == "primary@example.com"
        assert identity.email_verified is True
        assert identity.username == "octocat"
        assert identity.name == "Octo Cat"
        # OAuth Apps issue user-scoped tokens — there is no normalized
        # tenancy concept. Assert ``()`` explicitly so a future change
        # that synthesizes a tenant from org membership trips this test.
        assert identity.tenancies == ()

    async def test_fetch_identity_unsupported_provider_raises(self):
        config = _make_config(
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(TokenSet(access_token="access-abc"))

    async def test_fetch_identity_custom_handler(self):
        class DummyIdentityHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                assert material.access_token == "access-abc"
                assert config.client_id == "test-client"
                return IdentityProfile(email="custom@example.com")

        config = _make_config(
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        client = OAuthClient(config=config, identity_handler=DummyIdentityHandler())

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity.email == "custom@example.com"

    async def test_fetch_identity_infers_the_handler_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The client keeps the handler it inferred, so a handler's caches serve every sign-in."""
        built: list[object] = []

        class DummyIdentityHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                return IdentityProfile(email="inferred@example.com")

        def infer(config: ProviderConfig) -> DummyIdentityHandler:
            built.append(config)
            return DummyIdentityHandler()

        monkeypatch.setattr("apron_auth.client.infer_identity_handler", infer)
        client = OAuthClient(config=_make_config())

        await client.fetch_identity(TokenSet(access_token="access-abc"))
        await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert len(built) == 1

    async def test_fetch_identity_remembers_that_no_handler_was_inferred(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A config with no built-in handler is not inferred again on every call."""
        calls: list[ProviderConfig] = []

        def infer(config: ProviderConfig) -> None:
            calls.append(config)

        monkeypatch.setattr("apron_auth.client.infer_identity_handler", infer)
        client = OAuthClient(config=_make_config())

        for _ in range(2):
            with pytest.raises(IdentityNotSupportedError):
                await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert len(calls) == 1

    async def test_fetch_identity_provider_error_wrapped(self, httpx_mock):
        httpx_mock.add_response(
            url="https://www.googleapis.com/oauth2/v3/userinfo",
            status_code=401,
            json={"error": "invalid_token"},
        )
        config = _make_config(
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityFetchError, match="Failed to fetch Google identity"):
            await client.fetch_identity(TokenSet(access_token="bad-token"))

    async def test_fetch_identity_lookalike_google_host_not_inferred(self):
        config = _make_config(
            authorize_url="https://evilgoogle.com/authorize",
            token_url="https://evilgoogle.com/token",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(TokenSet(access_token="access-abc"))

    async def test_fetch_identity_lookalike_github_host_not_inferred(self):
        config = _make_config(
            authorize_url="https://evilgithub.com/login/oauth/authorize",
            token_url="https://evilgithub.com/login/oauth/access_token",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(TokenSet(access_token="access-abc"))

    async def test_microsoft_identity_inferred_from_config(self, httpx_mock):
        httpx_mock.add_response(
            url="https://graph.microsoft.com/oidc/userinfo",
            json={
                "sub": "ms-user-123",
                "email": "user@example.com",
                "name": "Test User",
                "picture": "https://example.com/avatar.png",
            },
        )
        config = _make_config(
            authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        )
        client = OAuthClient(config=config)

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity == IdentityProfile(
            provider="microsoft",
            subject="ms-user-123",
            email="user@example.com",
            email_verified=None,
            name="Test User",
            avatar_url="https://example.com/avatar.png",
            raw={
                "sub": "ms-user-123",
                "email": "user@example.com",
                "name": "Test User",
                "picture": "https://example.com/avatar.png",
            },
        )

    async def test_fetch_identity_lookalike_microsoft_host_not_inferred(self):
        config = _make_config(
            authorize_url="https://evilmicrosoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://evilmicrosoftonline.com/common/oauth2/v2.0/token",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(TokenSet(access_token="access-abc"))

    async def test_atlassian_identity_inferred_from_config(self, httpx_mock):
        payload = {
            "account_id": "557058:abc-123",
            "email": "user@example.com",
            "name": "Test User",
            "nickname": "tuser",
            "picture": "https://example.com/avatar.png",
            "account_type": "atlassian",
            "account_status": "active",
        }
        httpx_mock.add_response(url="https://api.atlassian.com/me", json=payload)
        httpx_mock.add_response(
            url="https://api.atlassian.com/oauth/token/accessible-resources",
            json=[],
        )
        config = _make_config(
            authorize_url="https://auth.atlassian.com/authorize",
            token_url="https://auth.atlassian.com/oauth/token",
        )
        client = OAuthClient(config=config)

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity == IdentityProfile(
            provider="atlassian",
            subject="557058:abc-123",
            email="user@example.com",
            email_verified=None,
            name="Test User",
            username="tuser",
            avatar_url="https://example.com/avatar.png",
            tenancies=(),
            raw=payload,
        )

    async def test_fetch_identity_lookalike_atlassian_host_not_inferred(self):
        config = _make_config(
            authorize_url="https://evilatlassian.com/authorize",
            token_url="https://evilatlassian.com/oauth/token",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(TokenSet(access_token="access-abc"))

    async def test_typeform_identity_inferred_from_config(self, httpx_mock):
        payload = {
            "alias": "octouser",
            "email": "user@example.com",
            "language": "en",
        }
        httpx_mock.add_response(url="https://api.typeform.com/me", json=payload)
        config = _make_config(
            authorize_url="https://api.typeform.com/oauth/authorize",
            token_url="https://api.typeform.com/oauth/token",
            use_pkce=False,
        )
        client = OAuthClient(config=config)

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity == IdentityProfile(
            provider="typeform",
            subject=None,
            email="user@example.com",
            email_verified=None,
            name=None,
            username="octouser",
            avatar_url=None,
            raw=payload,
        )

    async def test_typeform_scope_not_granted_propagates_from_token_set(self) -> None:
        config = _make_config(
            authorize_url="https://api.typeform.com/oauth/authorize",
            token_url="https://api.typeform.com/oauth/token",
            scopes=["accounts:read", "forms:read"],
            use_pkce=False,
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityScopeNotGrantedError):
            await client.fetch_identity(TokenSet(access_token="access-abc", scope="forms:read"))

    async def test_fetch_identity_lookalike_typeform_host_not_inferred(self):
        config = _make_config(
            authorize_url="https://eviltypeform.com/oauth/authorize",
            token_url="https://eviltypeform.com/oauth/token",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(TokenSet(access_token="access-abc"))

    async def test_notion_fetch_identity_lookalike_notion_host_not_inferred(self):
        config = _make_config(
            authorize_url="https://api.notion.com.attacker.test/v1/oauth/authorize",
            token_url="https://api.notion.com.attacker.test/v1/oauth/token",
            token_endpoint_auth_method="client_secret_basic",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(TokenSet(access_token="access-abc"))

    async def test_notion_identity_inferred_from_config(self, httpx_mock):
        payload = {
            "object": "user",
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "Integration Bot",
            "avatar_url": "https://example.com/notion-bot.png",
            "type": "bot",
            "bot": {
                "owner": {
                    "type": "user",
                    "user": {
                        "id": "22222222-2222-2222-2222-222222222222",
                        "name": "Notion Owner",
                        "person": {"email": "owner@example.com"},
                    },
                },
                "workspace_id": "33333333-3333-3333-3333-333333333333",
                "workspace_name": "Example Workspace",
            },
        }
        httpx_mock.add_response(url="https://api.notion.com/v1/users/me", json=payload)
        config = _make_config(
            authorize_url="https://api.notion.com/v1/oauth/authorize",
            token_url="https://api.notion.com/v1/oauth/token",
            token_endpoint_auth_method="client_secret_basic",
        )
        client = OAuthClient(config=config)

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity == IdentityProfile(
            provider="notion",
            subject="22222222-2222-2222-2222-222222222222",
            email="owner@example.com",
            email_verified=None,
            name="Notion Owner",
            username=None,
            avatar_url="https://example.com/notion-bot.png",
            tenancies=(
                TenancyContext(
                    id="33333333-3333-3333-3333-333333333333",
                    name="Example Workspace",
                ),
            ),
            raw=payload,
        )

    async def test_salesforce_identity_inferred_from_config(self, httpx_mock):
        payload = {
            "sub": "https://login.salesforce.com/id/00Dxx0000001gZWEAY/005xx000001SwiUAAS",
            "email": "user@example.com",
            "email_verified": True,
            "name": "Test User",
            "nickname": "tuser",
            "picture": "https://example.com/avatar.png",
            "user_id": "005xx000001SwiUAAS",
            "organization_id": "00Dxx0000001gZWEAY",
            "urls": {"rest": "https://acme.my.salesforce.com/services/data/v{version}/"},
        }
        httpx_mock.add_response(url="https://login.salesforce.com/services/oauth2/userinfo", json=payload)
        config = _make_config(
            authorize_url="https://login.salesforce.com/services/oauth2/authorize",
            token_url="https://login.salesforce.com/services/oauth2/token",
        )
        client = OAuthClient(config=config)

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity == IdentityProfile(
            provider="salesforce",
            subject="https://login.salesforce.com/id/00Dxx0000001gZWEAY/005xx000001SwiUAAS",
            email="user@example.com",
            email_verified=True,
            name="Test User",
            username="tuser",
            avatar_url="https://example.com/avatar.png",
            tenancies=(
                TenancyContext(
                    id="00Dxx0000001gZWEAY",
                    domain="login.salesforce.com",
                ),
            ),
            raw=payload,
        )

    async def test_salesforce_my_domain_identity_inferred(self, httpx_mock):
        httpx_mock.add_response(
            url="https://acme.my.salesforce.com/services/oauth2/userinfo",
            json={"sub": "https://acme.my.salesforce.com/id/X/Y", "email": "user@acme.com"},
        )
        config = _make_config(
            authorize_url="https://acme.my.salesforce.com/services/oauth2/authorize",
            token_url="https://acme.my.salesforce.com/services/oauth2/token",
        )
        client = OAuthClient(config=config)

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity.provider == "salesforce"
        assert identity.email == "user@acme.com"

    async def test_fetch_identity_lookalike_salesforce_host_not_inferred(self):
        config = _make_config(
            authorize_url="https://evilsalesforce.com/services/oauth2/authorize",
            token_url="https://evilsalesforce.com/services/oauth2/token",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(TokenSet(access_token="access-abc"))

    async def test_linear_identity_inferred_from_config(self, httpx_mock):
        viewer = {
            "id": "user-123",
            "name": "Linear User",
            "displayName": "luser",
            "email": "user@example.com",
            "avatarUrl": "https://example.com/avatar.png",
        }
        httpx_mock.add_response(
            url="https://api.linear.app/graphql",
            json={"data": {"viewer": viewer}},
        )
        config = _make_config(
            authorize_url="https://linear.app/oauth/authorize",
            token_url="https://api.linear.app/oauth/token",
        )
        client = OAuthClient(config=config)

        identity = await client.fetch_identity(TokenSet(access_token="access-abc"))

        assert identity == IdentityProfile(
            provider="linear",
            subject="user-123",
            email="user@example.com",
            email_verified=None,
            name="Linear User",
            username="luser",
            avatar_url="https://example.com/avatar.png",
            raw=viewer,
        )

    async def test_fetch_identity_lookalike_linear_host_not_inferred(self):
        config = _make_config(
            authorize_url="https://linear.app.attacker.test/oauth/authorize",
            token_url="https://linear.app.attacker.test/oauth/token",
        )
        client = OAuthClient(config=config)

        with pytest.raises(IdentityNotSupportedError):
            await client.fetch_identity(TokenSet(access_token="access-abc"))

    async def test_fetch_identity_custom_handler_unexpected_error_wrapped(self):
        class BoomHandler:
            async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
                raise RuntimeError("boom")

        config = _make_config(
            authorize_url="https://provider.example.com/authorize",
            token_url="https://provider.example.com/token",
        )
        client = OAuthClient(config=config, identity_handler=BoomHandler())

        with pytest.raises(IdentityFetchError, match="^Failed to fetch identity$") as exc_info:
            await client.fetch_identity(TokenSet(access_token="access-abc"))
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None
