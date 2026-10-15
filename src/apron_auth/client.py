"""OAuth 2.0 client for authorization code flows."""

from __future__ import annotations

import hmac
import json
import secrets
import time
from functools import cached_property
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from apron_auth._http_errors import describe_http_error
from apron_auth._jwt import unverified_claims
from apron_auth.errors import (
    INVALID_CLIENT,
    INVALID_GRANT,
    UNAUTHORIZED_CLIENT,
    ConfigurationError,
    IdentityFetchError,
    IdentityNotSupportedError,
    NonceValidationError,
    PermanentOAuthError,
    RevocationError,
    StateError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import IdentityMaterial, OAuthPendingState, TokenSet
from apron_auth.pkce import generate_code_challenge, generate_code_verifier
from apron_auth.protocols import StandardRevocationHandler
from apron_auth.providers.identity import infer_identity_handler
from apron_auth.scopes import join_scopes

if TYPE_CHECKING:
    from collections.abc import Mapping

    from apron_auth.models import IdentityProfile, ProviderConfig
    from apron_auth.protocols import IdentityHandler, RevocationHandler, StateStore, TransportFactory


class _TokenEndpointError(Exception):
    """Internal exception carrying the OAuth error code from the token endpoint."""

    def __init__(self, message: str, error_code: str = "") -> None:
        """Create the error.

        Args:
            message: Human-readable description of the failure.
            error_code: The OAuth error code from the token endpoint when
                one is available, else an empty string.
        """
        super().__init__(message)
        self.error_code = error_code


def _check_nonce(id_token: object, nonce: str) -> None:
    """Refuse an ID token that does not carry the nonce sent with its authorization request.

    NOTE: Callers must pass only an ID token the token endpoint returned, because its signature is not checked.

    Args:
        id_token: The ``id_token`` value from a token-endpoint response.
        nonce: The nonce sent with the authorization request.

    Raises:
        NonceValidationError: If the ID token cannot be read, carries no nonce, or carries a different one.
    """
    msg = "ID token could not be read to check its nonce"
    if not isinstance(id_token, str):
        raise NonceValidationError(msg)
    try:
        claims = unverified_claims(id_token)
    except ValueError:
        claims = None
    # NOTE: This check raises outside the except block, so the error does not chain the decoder's error.
    if claims is None:
        raise NonceValidationError(msg)
    claim = claims.get("nonce")
    if claim is None:
        msg = "ID token carries no nonce for the authorization request"
        raise NonceValidationError(msg)
    if not isinstance(claim, str) or not _same_secret(claim, nonce):
        msg = "ID token nonce does not match the authorization request"
        raise NonceValidationError(msg)


def _same_secret(given: str, expected: str) -> bool:
    """Return whether two secret strings are equal, in time that does not depend on where they differ.

    Any two strings compare without raising, including ones that are not valid UTF-8 text.

    Args:
        given: The value received from outside.
        expected: The value this client issued.

    Returns:
        ``True`` when the strings are equal.
    """
    return hmac.compare_digest(given.encode("utf-8", "surrogatepass"), expected.encode("utf-8", "surrogatepass"))


class OAuthClient:
    """OAuth 2.0 client for authorization code flows, which keeps no per-user state.

    NOTE: Callers must not use one client from event loops in several threads at once,
    because the identity handler it infers may keep caches that are not thread-safe.
    """

    DEFAULT_PERMANENT_ERROR_CODES = frozenset({INVALID_GRANT, UNAUTHORIZED_CLIENT, INVALID_CLIENT})

    def __init__(
        self,
        config: ProviderConfig,
        state_store: StateStore | None = None,
        revocation_handler: RevocationHandler | None = None,
        identity_handler: IdentityHandler | None = None,
        permanent_error_codes: set[str] | None = None,
        transport_factory: TransportFactory | None = None,
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
            transport_factory: Optional factory returning an httpx transport for
                a URL, used for token-endpoint requests. Lets the caller control
                the outbound connection (e.g. pin DNS to validated public IPs)
                when the token endpoint comes from untrusted discovery.
        """
        self._config = config
        self._state_store = state_store
        self._revocation_handler = revocation_handler
        self._identity_handler = identity_handler
        self._permanent_error_codes = self.DEFAULT_PERMANENT_ERROR_CODES | (permanent_error_codes or set())
        self._transport_factory = transport_factory

    async def get_authorization_url(
        self,
        redirect_uri: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, OAuthPendingState]:
        """Build an authorization URL with state, optional PKCE, and a nonce when the request asks for ``openid``.

        If a ``StateStore`` is configured, the pending state is saved
        automatically before returning.

        Args:
            redirect_uri: Override the redirect URI from ``ProviderConfig``.
            metadata: Opaque caller context attached to the pending state.

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

        params.update(self._scope_params())

        if self._config.use_pkce:
            code_verifier = generate_code_verifier()
            params["code_challenge"] = generate_code_challenge(code_verifier)
            params["code_challenge_method"] = "S256"

        query = self._authorization_query(params)

        # The nonce is set on the built query, because the decision depends on its final scope
        # and extra_params must not be able to replace it.
        nonce = None
        if self._sends_openid(query):
            nonce = secrets.token_urlsafe(32)
            query["nonce"] = nonce

        parsed = urlparse(self._config.authorize_url)
        url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

        pending_state = OAuthPendingState(
            state=state,
            redirect_uri=effective_redirect_uri,
            code_verifier=code_verifier,
            nonce=nonce,
            created_at=time.time(),
            metadata=metadata or {},
        )

        if self._state_store is not None:
            await self._state_store.save(pending_state)

        return url, pending_state

    async def exchange_code(
        self,
        code: str,
        state: str,
        *,
        pending_state: OAuthPendingState | None = None,
        iss: str | None = None,
    ) -> TokenSet:
        """Exchange an authorization code for tokens.

        A client with a ``StateStore`` consumes the pending state for ``state`` from it.
        A client without one takes ``pending_state``.
        Either way, a ``state`` that does not match the pending state is refused before the code is redeemed.
        When the authorization request sent a nonce, an ID token in the response must carry it,
        or no tokens are returned.
        A response without an ID token is returned without a nonce check.

        When the provider carries an expected issuer, the authorization-response ``iss`` (RFC 9207) is validated first.
        A mix-up attempt is then refused before any state is consumed and before the token endpoint is called.

        NOTE: Callers must keep their own pending state where the user cannot change it,
        because every check here trusts it.
        Callers must also discard it after one exchange attempt, even a failed one,
        because only a ``StateStore`` refuses a pending state that is reused or too old.

        Args:
            code: The authorization code returned to the redirect URI.
            state: The ``state`` parameter from the callback.
            pending_state: The pending state that :meth:`get_authorization_url` returned, when the client has no store.
            iss: The ``iss`` parameter from the authorization response, to
                validate against the provider's expected issuer. Omit when
                the provider has no expected issuer configured.

        Returns:
            The exchanged token set.
            Any caller context stored with the pending state is surfaced on :attr:`TokenSet.context`.

        Raises:
            ConfigurationError: If ``pending_state`` is given to a client with a ``StateStore``,
                or is not given to a client without one.
            IssuerValidationError: If ``iss`` fails validation against the
                provider's expected issuer.
            NonceValidationError: If the response's ID token does not carry the nonce the request sent,
                or the pending state of an OpenID request has no nonce.
            StateError: If the callback carried no state, ``state`` does not match ``pending_state``,
                or the store holds no pending state for it because it is invalid, expired, or already consumed.
            TokenExchangeError: If the token endpoint rejects the exchange.
                It does not chain the failed request's error.
        """
        self._config.validate_issuer(iss)
        pending = await self._resolve_pending_state(state, pending_state)

        data: dict[str, str] = {"grant_type": "authorization_code", "code": code}
        if pending.redirect_uri:
            data["redirect_uri"] = pending.redirect_uri
        if pending.code_verifier:
            data["code_verifier"] = pending.code_verifier
        if self._config.resource is not None:
            data["resource"] = self._config.resource

        try:
            response = await self._token_request(data)
        except _TokenEndpointError as exc:
            raise TokenExchangeError(str(exc), error_code=exc.error_code) from exc
        id_token = response.get("id_token")
        if id_token is not None:
            if pending.nonce:
                _check_nonce(id_token, pending.nonce)
            elif self._requests_openid():
                msg = "The pending state has no nonce to check the ID token against"
                raise NonceValidationError(msg)
        return self._parse_token_response(response, context=pending.metadata)

    async def refresh_token(self, refresh_token: str) -> TokenSet:
        """Refresh an access token using a refresh token.

        Args:
            refresh_token: The refresh token to exchange for a new access
                token.

        Returns:
            The refreshed token set.

        Raises:
            PermanentOAuthError: If the endpoint reports an error whose code
                is in the configured permanent set (such as ``invalid_grant``);
                retrying the identical request will not succeed. Read
                ``error_code`` to decide how to handle it.
            TokenRefreshError: If the refresh fails transiently and a
                retry may succeed.
                It does not chain the failed request's error.
        """
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        if self._config.resource is not None:
            data["resource"] = self._config.resource
        try:
            response = await self._token_request(data)
        except _TokenEndpointError as exc:
            if exc.error_code in self._permanent_error_codes:
                raise PermanentOAuthError(str(exc), error_code=exc.error_code) from exc
            raise TokenRefreshError(str(exc), error_code=exc.error_code) from exc
        return self._parse_token_response(response)

    async def revoke_token(self, token: str) -> bool:
        """Revoke a token via the provider's revocation endpoint.

        Uses the configured RevocationHandler, or falls back to
        StandardRevocationHandler (RFC 7009 POST).

        Args:
            token: The token to revoke.

        Returns:
            ``True`` when the provider confirms revocation.

        Raises:
            ConfigurationError: If the provider has no revocation endpoint
                configured.
            RevocationError: If the revocation request fails or the
                provider does not confirm it.
                It chains nothing from the handler.
        """
        if not self._config.revocation_url:
            msg = "revocation_url is not configured for this provider"
            raise ConfigurationError(msg)

        handler = self._revocation_handler
        if handler is None:
            handler = StandardRevocationHandler(transport_factory=self._transport_factory)

        try:
            result = await handler.revoke(token, self._config)
        except RevocationError as exc:
            # NOTE: A handler's own error can chain a request that carries the token.
            exc.__cause__ = None
            exc.__context__ = None
            raise
        except httpx.HTTPError as exc:
            failure_message = f"Failed to revoke token: {describe_http_error(exc)}"
        except Exception:
            failure_message = "Failed to revoke token"
        else:
            if not result:
                msg = "Token revocation failed"
                raise RevocationError(msg)
            return True
        # NOTE: The caught error can hold the request, which carries the token, so this error must not reference it.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise RevocationError(failure_message)

    async def fetch_identity(self, tokens: TokenSet) -> IdentityProfile:
        """Fetch normalized user identity fields from the provider API.

        Pass the :class:`TokenSet` returned by :meth:`exchange_code` (or
        :meth:`refresh_token`). It is narrowed to an
        :class:`IdentityMaterial` — exposing only the access token, the
        granted scopes, and, for OIDC providers, the ID token — before
        being handed to the identity handler, so handlers never receive
        the refresh token or caller context.

        Uses the configured identity handler when provided, otherwise tries
        to infer a built-in handler from the provider endpoints.
        A config may disallow that inference, which leaves the configured handler as the only source of identity.

        NOTE: Callers must pass a token set straight from :meth:`exchange_code` or :meth:`refresh_token`.
        They must never pass one reloaded from storage or built from untrusted input.
        An identity handler may accept the ID token in it without a signature check,
        which is safe only for a token the token endpoint returned over TLS.

        Args:
            tokens: The token set from :meth:`exchange_code` or
                :meth:`refresh_token` to establish identity from.

        Returns:
            The normalized identity profile.

        Raises:
            IdentityNotSupportedError: If no identity handler is configured
                and none can be inferred for the provider.
                That includes a config that disallows inference.
            ConfigurationError: If built-in inference matches more than one
                provider for the configuration.
            IdentityFetchError: If the handler fails to fetch identity.
                It chains nothing from the handler.
        """
        handler = self._identity_handler or self._inferred_identity_handler
        if handler is None:
            msg = "No identity handler is available for this provider configuration"
            raise IdentityNotSupportedError(msg)
        material = IdentityMaterial.from_token_set(tokens)
        try:
            return await handler.fetch_identity(material, self._config)
        except IdentityFetchError as exc:
            # NOTE: A handler's own error can chain a request that carries the token.
            exc.__cause__ = None
            exc.__context__ = None
            raise
        except httpx.HTTPError as exc:
            failure_message = f"Failed to fetch identity: {describe_http_error(exc)}"
        except Exception:
            failure_message = "Failed to fetch identity"
        # NOTE: The caught error can hold the request, which carries the token, so this error must not reference it.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise IdentityFetchError(failure_message)

    @cached_property
    def _inferred_identity_handler(self) -> IdentityHandler | None:
        """Return the built-in handler inferred for this config, inferring it on first use.

        Keeping one handler lets its caches, such as an issuer's signing keys, serve every sign-in.

        Returns:
            The inferred handler, or ``None`` when no built-in provider matches the config.
        """
        return infer_identity_handler(self._config)

    def _authorization_query(self, params: dict[str, str]) -> dict[str, str | list[str]]:
        """Return the query of an authorization URL that sends ``params``.

        The authorization URL's own query is overridden by ``params``, then by ``extra_params``, then by the resource.

        Args:
            params: The request parameters this client sets.

        Returns:
            The query, with each parameter's value or values.
        """
        query: dict[str, str | list[str]] = {
            name: values[0] if len(values) == 1 else values
            for name, values in parse_qs(urlparse(self._config.authorize_url).query).items()
        }
        query.update(params)
        query.update(self._config.extra_params)
        # The resource indicator (RFC 8707) is authoritative for audience binding,
        # so extra_params must not be able to suppress or redirect it.
        if self._config.resource is not None:
            query["resource"] = self._config.resource
        return query

    def _requests_openid(self) -> bool:
        """Return whether this client's authorization request asks for the ``openid`` scope.

        Returns:
            ``True`` when a scope word the request sends is ``openid``.
        """
        return self._sends_openid(self._authorization_query(self._scope_params()))

    async def _resolve_pending_state(self, state: str, pending_state: OAuthPendingState | None) -> OAuthPendingState:
        """Return the pending state that matches the callback's state.

        Args:
            state: The ``state`` parameter from the callback.
            pending_state: The pending state the caller kept, or ``None`` when the ``StateStore`` keeps it.

        Returns:
            The pending state consumed from the store for ``state``, or the given one when the client has no store.

        Raises:
            ConfigurationError: If ``pending_state`` is given to a client with a ``StateStore``,
                or is not given to a client without one.
            StateError: If the callback carried no state, the store holds no pending state for it,
                or ``state`` does not match ``pending_state``.
        """
        if not isinstance(state, str) or not state:
            msg = "OAuth callback carried no usable state"
            raise StateError(msg)
        if self._state_store is not None:
            if pending_state is not None:
                msg = "This client looks up the pending state in its state store, so pass only the state"
                raise ConfigurationError(msg)
            pending = await self._state_store.consume(state)
            if pending is None or not _same_secret(state, pending.state):
                msg = "OAuth state is invalid, expired, or already consumed"
                raise StateError(msg)
            return pending
        if pending_state is None:
            msg = "Pass the pending state, or configure a state store to look it up"
            raise ConfigurationError(msg)
        if not _same_secret(state, pending_state.state):
            msg = "OAuth state does not match the pending authorization request"
            raise StateError(msg)
        return pending_state

    def _scope_params(self) -> dict[str, str]:
        """Return the ``scope`` request parameter for the configured scopes.

        Returns:
            The parameter, or no parameter when no scopes are configured.
        """
        if not self._config.scopes:
            return {}
        return {"scope": join_scopes(self._config.scopes, self._config.scope_separator)}

    def _sends_openid(self, query: Mapping[str, str | list[str]]) -> bool:
        """Return whether an authorization query asks for the ``openid`` scope.

        A scope word is delimited by whitespace (RFC 6749 section 3.3), a comma, or the configured separator.
        A wider set of delimiters only sends a nonce more often, which a provider that does not use OpenID ignores.

        Args:
            query: The query of an authorization URL.

        Returns:
            ``True`` when a scope word in ``query`` is ``openid``.
        """
        scope = query.get("scope")
        values = [scope] if isinstance(scope, str) else scope or []
        delimiters = {",", self._config.scope_separator} - {""}
        words: set[str] = set()
        for value in values:
            for delimiter in delimiters:
                value = value.replace(delimiter, " ")
            words.update(value.split())
        return "openid" in words

    async def _token_request(self, data: dict[str, str]) -> dict:
        """Send a token request via authlib's AsyncOAuth2Client.

        Authlib handles token_endpoint_auth_method (client_secret_post vs
        client_secret_basic), request encoding, and response parsing.

        Args:
            data: The grant-specific form fields for the request (e.g.
                ``grant_type`` and the authorization code or refresh token).

        Returns:
            The token-endpoint response as a plain dict.

        Raises:
            _TokenEndpointError: If the endpoint returns an OAuth error,
                fails with a non-success status, or the request otherwise
                errors; its ``error_code`` carries the OAuth error code
                when one is available.
                The caught error is not attached as its cause or context.
        """
        from authlib.integrations.base_client.errors import OAuthError
        from authlib.integrations.httpx_client import AsyncOAuth2Client

        try:
            client_secret = self._config.client_secret
            transport = self._transport_factory(self._config.token_url) if self._transport_factory is not None else None
            async with AsyncOAuth2Client(
                client_id=self._config.client_id,
                client_secret=client_secret.get_secret_value() if client_secret is not None else None,
                token_endpoint_auth_method=self._config.token_endpoint_auth_method,
                transport=transport,
            ) as client:
                token = await client.fetch_token(self._config.token_url, **data)
            return dict(token)
        except OAuthError as exc:
            # Authlib raises OAuthError for 4xx responses that contain an
            # OAuth error body ({"error": "...", "error_description": "..."}).
            # The .error attribute carries the OAuth error code (e.g.
            # "invalid_grant") which refresh_token uses to distinguish
            # permanent from transient failures.
            error_code = exc.error if isinstance(exc.error, str) else ""
            description = exc.description if isinstance(exc.description, str) else ""
            prefix = error_code or "unspecified token endpoint error"
            msg = f"{prefix}: {description}" if description else prefix
            failure = _TokenEndpointError(msg, error_code=error_code)
        except httpx.HTTPStatusError as exc:
            # Authlib calls raise_for_status() for 5xx responses, producing
            # an httpx.HTTPStatusError. We attempt to extract the OAuth
            # error code from the response body if present.
            error_code = ""
            msg = f"HTTP {exc.response.status_code}"
            try:
                body = exc.response.json()
                raw_error_code = body.get("error", "")
                error_code = raw_error_code if isinstance(raw_error_code, str) else ""
                raw_description = body.get("error_description", "")
                description = raw_description if isinstance(raw_description, str) else ""
                prefix = error_code or msg
                msg = f"{prefix}: {description}" if description else prefix
            except Exception:
                pass
            failure = _TokenEndpointError(msg, error_code=error_code)
        except httpx.RequestError as exc:
            failure = _TokenEndpointError(describe_http_error(exc), error_code="")
        except json.JSONDecodeError:
            failure = _TokenEndpointError("token response could not be read", error_code="")
        except Exception:
            failure = _TokenEndpointError("request failed", error_code="")
        # NOTE: The caught error can hold the request, which carries the client secret and the grant.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise failure

    def _parse_token_response(self, data: dict, context: dict[str, Any] | None = None) -> TokenSet:
        """Parse a token endpoint response into a TokenSet.

        Args:
            data: A token-endpoint response.
            context: Caller context to carry onto :attr:`TokenSet.context`;
                treated as empty when ``None``.

        Returns:
            The parsed token set. Response fields with no named slot are
            collected into :attr:`TokenSet.metadata`, and ``expires_at`` is
            derived from ``expires_in`` when the response omits it.
        """
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
