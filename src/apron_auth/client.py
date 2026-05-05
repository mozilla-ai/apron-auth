"""OAuth 2.0 client for authorization code flows."""

from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from apron_auth.errors import (
    ConfigurationError,
    IdentityFetchError,
    IdentityNotSupportedError,
    PermanentOAuthError,
    RevocationError,
    StateError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import OAuthPendingState, TokenSet
from apron_auth.pkce import generate_code_challenge, generate_code_verifier
from apron_auth.protocols import StandardRevocationHandler
from apron_auth.providers.identity import infer_identity_handler
from apron_auth.scopes import join_scopes

if TYPE_CHECKING:
    from apron_auth.models import IdentityProfile, ProviderConfig
    from apron_auth.protocols import IdentityHandler, RevocationHandler, StateStore


class _TokenEndpointError(Exception):
    """Internal exception carrying the OAuth error code from the token endpoint."""

    def __init__(self, message: str, error_code: str = "") -> None:
        super().__init__(message)
        self.error_code = error_code


class OAuthClient:
    """Stateless OAuth 2.0 client for authorization code flows."""

    DEFAULT_PERMANENT_ERROR_CODES = frozenset({"invalid_grant", "unauthorized_client", "invalid_client"})

    def __init__(
        self,
        config: ProviderConfig,
        state_store: StateStore | None = None,
        revocation_handler: RevocationHandler | None = None,
        identity_handler: IdentityHandler | None = None,
        permanent_error_codes: set[str] | None = None,
    ) -> None:
        """Create an OAuth client.

        Args:
            config: Provider endpoints, credentials, and behavior.
            state_store: Optional persistence for OAuth state across requests.
            revocation_handler: Optional provider-specific token revocation.
            identity_handler: Optional provider-specific identity fetcher.
            permanent_error_codes: Additional OAuth error codes that should be
                treated as irrecoverable during token refresh. These merge
                with, rather than replace, DEFAULT_PERMANENT_ERROR_CODES.
        """
        self._config = config
        self._state_store = state_store
        self._revocation_handler = revocation_handler
        self._identity_handler = identity_handler
        self._permanent_error_codes = self.DEFAULT_PERMANENT_ERROR_CODES | (permanent_error_codes or set())

    async def get_authorization_url(
        self,
        redirect_uri: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, OAuthPendingState]:
        """Build an authorization URL with state and optional PKCE.

        If a ``StateStore`` is configured, the pending state is saved
        automatically before returning.

        Args:
            redirect_uri: Override the redirect URI from ``ProviderConfig``.
            metadata: Opaque caller context attached to the pending state.
                Carried through ``StateStore`` save/consume and surfaced
                on ``TokenSet.context`` when ``exchange_code`` auto-consumes.

        Returns:
            A tuple of the authorization URL and the pending state.

        Raises:
            ConfigurationError: If no redirect URI is available.
        """
        effective_redirect_uri = redirect_uri or self._config.redirect_uri
        if not effective_redirect_uri:
            msg = "redirect_uri must be provided either in the method call or in ProviderConfig"
            raise ConfigurationError(msg)

        state = secrets.token_urlsafe(32)
        code_verifier = None

        params: dict[str, str] = {
            "client_id": self._config.client_id,
            "response_type": "code",
            "redirect_uri": effective_redirect_uri,
            "state": state,
        }

        if self._config.scopes:
            params["scope"] = join_scopes(self._config.scopes, self._config.scope_separator)

        if self._config.use_pkce:
            code_verifier = generate_code_verifier()
            params["code_challenge"] = generate_code_challenge(code_verifier)
            params["code_challenge_method"] = "S256"

        params.update(self._config.extra_params)

        parsed = urlparse(self._config.authorize_url)
        existing_params = parse_qs(parsed.query)
        merged = {k: v[0] if len(v) == 1 else v for k, v in existing_params.items()}
        merged.update(params)
        url = urlunparse(parsed._replace(query=urlencode(merged, doseq=True)))

        pending_state = OAuthPendingState(
            state=state,
            redirect_uri=effective_redirect_uri,
            code_verifier=code_verifier,
            created_at=time.time(),
            metadata=metadata or {},
        )

        if self._state_store is not None:
            await self._state_store.save(pending_state)

        return url, pending_state

    async def exchange_code(
        self,
        code: str,
        state: str | None = None,
        redirect_uri: str | None = None,
        code_verifier: str | None = None,
    ) -> TokenSet:
        """Exchange an authorization code for tokens.

        Two modes:
        - Pass state to consume from StateStore and retrieve stored
          redirect_uri and code_verifier.
        - Pass redirect_uri and code_verifier directly.
        """
        context: dict[str, Any] = {}
        if state is not None and self._state_store is not None:
            pending = await self._state_store.consume(state)
            if pending is None:
                msg = "OAuth state is invalid, expired, or already consumed"
                raise StateError(msg)
            redirect_uri = pending.redirect_uri
            code_verifier = pending.code_verifier
            context = pending.metadata

        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
        }
        if redirect_uri:
            data["redirect_uri"] = redirect_uri
        if code_verifier:
            data["code_verifier"] = code_verifier

        try:
            response = await self._token_request(data)
        except _TokenEndpointError as exc:
            raise TokenExchangeError(str(exc)) from exc
        return self._parse_token_response(response, context=context)

    async def refresh_token(self, refresh_token: str) -> TokenSet:
        """Refresh an access token using a refresh token.

        Raises PermanentOAuthError for irrecoverable failures
        (invalid_grant, unauthorized_client, invalid_client).
        Raises TokenRefreshError for transient failures.
        """
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        try:
            response = await self._token_request(data)
        except _TokenEndpointError as exc:
            if exc.error_code in self._permanent_error_codes:
                raise PermanentOAuthError(str(exc)) from exc
            raise TokenRefreshError(str(exc)) from exc
        except Exception as exc:
            raise TokenRefreshError(str(exc)) from exc
        return self._parse_token_response(response)

    async def revoke_token(self, token: str) -> bool:
        """Revoke a token via the provider's revocation endpoint.

        Uses the configured RevocationHandler, or falls back to
        StandardRevocationHandler (RFC 7009 POST).
        """
        if not self._config.revocation_url:
            msg = "revocation_url is not configured for this provider"
            raise ConfigurationError(msg)

        handler = self._revocation_handler
        if handler is None:
            handler = StandardRevocationHandler()

        try:
            result = await handler.revoke(token, self._config)
        except RevocationError:
            raise
        except Exception as exc:
            raise RevocationError(str(exc)) from exc
        if not result:
            msg = "Token revocation failed"
            raise RevocationError(msg)
        return True

    async def fetch_identity(self, access_token: str) -> IdentityProfile:
        """Fetch normalized user identity fields from the provider API.

        Uses the configured identity handler when provided, otherwise tries
        to infer a built-in handler from the provider endpoints.
        """
        handler = self._identity_handler or infer_identity_handler(self._config)
        if handler is None:
            msg = "No identity handler is available for this provider configuration"
            raise IdentityNotSupportedError(msg)
        try:
            return await handler.fetch_identity(access_token, self._config)
        except IdentityFetchError:
            raise
        except Exception as exc:
            raise IdentityFetchError(str(exc)) from exc

    async def _token_request(self, data: dict[str, str]) -> dict:
        """Send a token request via authlib's AsyncOAuth2Client.

        Authlib handles token_endpoint_auth_method (client_secret_post vs
        client_secret_basic), request encoding, and response parsing.
        Three error paths are possible — see inline comments.
        """
        from authlib.integrations.base_client.errors import OAuthError
        from authlib.integrations.httpx_client import AsyncOAuth2Client

        try:
            async with AsyncOAuth2Client(
                client_id=self._config.client_id,
                client_secret=self._config.client_secret.get_secret_value(),
                token_endpoint_auth_method=self._config.token_endpoint_auth_method,
            ) as client:
                token = await client.fetch_token(self._config.token_url, **data)
            return dict(token)
        except OAuthError as exc:
            # Authlib raises OAuthError for 4xx responses that contain an
            # OAuth error body ({"error": "...", "error_description": "..."}).
            # The .error attribute carries the OAuth error code (e.g.
            # "invalid_grant") which refresh_token uses to distinguish
            # permanent from transient failures.
            raise _TokenEndpointError(
                f"{exc.error}: {exc.description}" if exc.description else str(exc.error),
                error_code=str(exc.error),
            ) from exc
        except httpx.HTTPStatusError as exc:
            # Authlib calls raise_for_status() for 5xx responses, producing
            # an httpx.HTTPStatusError. We attempt to extract the OAuth
            # error code from the response body if present.
            error_code = ""
            msg = f"HTTP {exc.response.status_code}"
            try:
                body = exc.response.json()
                error_code = body.get("error", "")
                description = body.get("error_description", "")
                msg = f"{error_code}: {description}" if description else error_code or msg
            except Exception:
                pass
            raise _TokenEndpointError(msg, error_code=error_code) from exc
        except Exception as exc:
            # Network errors (ConnectError, TimeoutException), JSON decode
            # errors, or anything else. No error_code available.
            raise _TokenEndpointError(str(exc), error_code="") from exc

    def _parse_token_response(self, data: dict, context: dict[str, Any] | None = None) -> TokenSet:
        """Parse a token endpoint response into a TokenSet."""
        known_fields = {"access_token", "token_type", "refresh_token", "expires_in", "expires_at", "scope"}
        metadata = {k: v for k, v in data.items() if k not in known_fields}

        expires_at = data.get("expires_at")
        expires_in = data.get("expires_in")
        if expires_at is None and expires_in is not None:
            expires_at = time.time() + int(expires_in)

        return TokenSet(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            refresh_token=data.get("refresh_token"),
            expires_in=int(expires_in) if expires_in is not None else None,
            expires_at=expires_at,
            scope=data.get("scope"),
            metadata=metadata,
            context=context or {},
        )
