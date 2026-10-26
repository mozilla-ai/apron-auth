"""OAuth 2.0 client for authorization code flows."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import secrets
import time
from collections.abc import Sequence
from functools import cached_property
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, assert_never
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from apron_auth._authorization_params import authorization_query, scope_param, sent_scope_words
from apron_auth._clock import CLOCK_SKEW_SECONDS, PendingAgeRefusalReason, pending_age_refusal
from apron_auth._error_codes import recognized_error_code
from apron_auth._http_errors import http_failure, status_failure
from apron_auth._json_body import decode_json_body
from apron_auth._jwt import unverified_claims
from apron_auth._numbers import finite_number
from apron_auth._urls import AuthorityCredential, authority_credential, uses_allowed_transport
from apron_auth.errors import (
    SERVER_ERROR,
    TEMPORARILY_UNAVAILABLE,
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    IdentityNotSupportedError,
    IdTokenValidationError,
    NonceValidationError,
    OAuthError,
    RevocationError,
    StateError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import (
    FreshTokenSet,
    IdentityMaterial,
    OAuthPendingState,
    UrlField,
    UserToken,
)
from apron_auth.pkce import generate_code_challenge, generate_code_verifier
from apron_auth.protocols import StandardRevocationHandler
from apron_auth.providers import identity_handler_for

if TYPE_CHECKING:
    from collections.abc import Mapping

    from apron_auth.models import IdentityProfile, ProviderConfig
    from apron_auth.protocols import IdentityHandler, RevocationHandler, StateStore, TransportFactory

logger = logging.getLogger(__name__)

# The refusal of a token-endpoint response carrying no access token, which RFC 6749 section 5.1 requires.
_NO_ACCESS_TOKEN_REFUSAL = "token response states no access token"

# The wall-clock limit, in seconds, on revoking the tokens of a refused token response.
# NOTE: The exchange_code docstring states this value.
_REFUSED_TOKEN_REVOCATION_TIMEOUT_SECONDS = 10.0

# The grant fields of a token request that hold a secret.
_SENT_SECRET_FIELDS = ("code", "code_verifier", "refresh_token")

# The number fields a token-endpoint response states: a lifetime in seconds and a Unix timestamp.
_TOKEN_SET_NUMBERS = ("expires_at", "expires_in")

# The string fields a token-endpoint response states, beside the access token.
_TOKEN_SET_STRINGS = ("refresh_token", "scope", "token_type")

# The string members of a nested user token, each mapped to the UserToken field that states it.
# NOTE: It decides which member of a response becomes a named credential, so it is read-only.
_USER_TOKEN_STRINGS = MappingProxyType(
    {"id": "user_id", "refresh_token": "refresh_token", "scope": "scope", "token_type": "token_type"}
)


class _TokenEndpointError(Exception):
    """Internal exception carrying the OAuth error code from the token endpoint."""

    def __init__(self, message: str, kind: FailureKind, error_code: str = "") -> None:
        """Create the error.

        Args:
            message: Human-readable description of the failure.
            kind: What went wrong.
            error_code: The OAuth error code from the token endpoint when
                one is available, else an empty string.
        """
        super().__init__(message)
        self.kind = kind
        self.error_code = error_code


def _audience_names(audience: object) -> set[str] | None:
    """Return the names an ``aud`` claim lists, or ``None`` when it is not a name or a list of names.

    The members are checked before they are collected, because a member that is not a name may not be hashable.
    """
    if isinstance(audience, str):
        return {audience}
    if isinstance(audience, list) and all(isinstance(name, str) for name in audience):
        return set(audience)
    return None


async def _cancel_and_wait(tasks: Sequence[asyncio.Task[None]]) -> None:
    """Cancel the tasks that are still running, and wait until every task has finished.

    Args:
        tasks: The tasks to cancel and wait for.
    """
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.wait(tasks)


def _check_claims(claims: Mapping[str, Any], *, client_id: str, issuer: str | None) -> None:
    """Refuse ID token claims that were not issued to this client, or that are no longer valid.

    The checks follow OpenID Connect Core section 3.1.3.7: the issuer must match when one is known,
    the audience must name this client and no other party unless this client is the authorized party,
    and the expiry must lie ahead, within the allowed clock skew.

    Args:
        claims: The ID token's claims.
        client_id: This client's identifier.
        issuer: The issuer the token must name, or ``None`` when no issuer is known.

    Raises:
        IdTokenValidationError: If the claims name another issuer, audience or authorized party,
            the audience is not a name or a list of names, or the expiry is absent, not a number, or in the past.
    """
    if issuer is not None and claims.get("iss") != issuer:
        msg = "ID token issuer does not match the configured issuer"
        raise IdTokenValidationError(msg)
    audiences = _audience_names(claims.get("aud"))
    if audiences is None:
        msg = "ID token audience is not a name or a list of names"
        raise IdTokenValidationError(msg)
    if not audiences:
        msg = "ID token names no audience"
        raise IdTokenValidationError(msg)
    if client_id not in audiences:
        msg = "ID token audience does not include this client"
        raise IdTokenValidationError(msg)
    authorized_party = claims.get("azp")
    if len(audiences) > 1 and authorized_party is None:
        msg = "ID token names several audiences without an authorized party"
        raise IdTokenValidationError(msg)
    if authorized_party is not None and authorized_party != client_id:
        msg = "ID token authorized party is not this client"
        raise IdTokenValidationError(msg)
    expiry = finite_number(claims.get("exp"))
    if expiry is None or expiry + CLOCK_SKEW_SECONDS < time.time():
        msg = "ID token has expired or carries no usable expiry"
        raise IdTokenValidationError(msg)


def _check_id_token(id_token: object, nonce: str | None, *, client_id: str, issuer: str | None) -> None:
    """Refuse a token response whose ID token was not issued to this client for the request it answers.

    Every ID token the response carries has its claims checked. The nonce is checked only when the
    authorization request sent one, which is the OpenID case, and then the ID token is required.

    NOTE: The ID token's signature is not checked, which OpenID Connect Core section 3.1.3.7 allows
    only for a token received from the token endpoint over TLS, so the configured token endpoint must use it.

    Args:
        id_token: The ``id_token`` value from the token response, or ``None`` when it has none.
        nonce: The nonce the authorization request sent, or ``None`` when it sent none.
        client_id: This client's identifier.
        issuer: The issuer the token must name, or ``None`` when no issuer is known.

    Raises:
        IdTokenValidationError: If the ID token cannot be read, names another issuer, audience or
            authorized party, or has expired.
        NonceValidationError: If a nonce was sent and the response carries no ID token,
            or an ID token that does not carry that nonce.
    """
    if id_token is None:
        if not nonce:
            return
        # OpenID Connect Core section 3.1.3.3 requires an ID token, and without one no nonce is checked.
        msg = "Token response carries no ID token for the OpenID request"
        raise NonceValidationError(msg)
    claims = _id_token_claims(id_token)
    _check_claims(claims, client_id=client_id, issuer=issuer)
    if nonce:
        _check_nonce(claims, nonce)


def _check_nonce(claims: Mapping[str, Any], nonce: str) -> None:
    """Refuse ID token claims that do not carry the nonce sent with the authorization request.

    Args:
        claims: The ID token's claims.
        nonce: The nonce sent with the authorization request.

    Raises:
        NonceValidationError: If the claims carry no nonce, or a different one.
    """
    claim = claims.get("nonce")
    if claim is None:
        msg = "ID token carries no nonce for the authorization request"
        raise NonceValidationError(msg)
    if not isinstance(claim, str) or not _same_secret(claim, nonce):
        msg = "ID token nonce does not match the authorization request"
        raise NonceValidationError(msg)


def _check_pending_age(pending: OAuthPendingState, *, max_age: float) -> None:
    """Refuse a pending authorization request whose creation time is not current against the system clock.

    Args:
        pending: The pending authorization request to check.
        max_age: The age, in seconds, past which a pending authorization request is refused.
            It must be a positive number of seconds that can be subtracted from a clock reading.

    Raises:
        StateError: If the creation time fails any of the clock conditions for a pending request,
            worded for the condition it fails.
    """
    refusal = pending_age_refusal(pending.created_at, max_age=max_age)
    match refusal:
        case None:
            return
        case PendingAgeRefusalReason.AHEAD_OF_CLOCK:
            msg = "Pending authorization request was created ahead of this clock"
        case PendingAgeRefusalReason.TOO_OLD:
            msg = "Pending authorization request is older than the maximum age"
        case PendingAgeRefusalReason.UNUSABLE:
            msg = "Pending authorization request carries no usable creation time"
        case _:
            assert_never(refusal)
    raise StateError(msg)


def _expires_at(token: Mapping[str, Any]) -> float | None:
    """Return the absolute expiry a token states, derived from its lifetime where it states no expiry.

    Args:
        token: A token-endpoint response, or a member of one that carries a token of its own.

    Returns:
        The expiry as a Unix timestamp, or ``None`` where the token states neither an expiry nor a lifetime.
    """
    expires_at = finite_number(token.get("expires_at"))
    expires_in = finite_number(token.get("expires_in"))
    if expires_at is None and expires_in is not None:
        return time.time() + expires_in
    return expires_at


def _id_token_claims(id_token: object) -> dict[str, Any]:
    """Return the claims of an ID token from a token response, without checking its signature.

    Args:
        id_token: The ``id_token`` value from a token-endpoint response.

    Returns:
        The token's claims.

    Raises:
        IdTokenValidationError: If the ID token is not a string, or cannot be read.
    """
    msg = "ID token could not be read"
    if not isinstance(id_token, str):
        raise IdTokenValidationError(msg)
    try:
        return unverified_claims(id_token)
    except ValueError:
        pass
    # NOTE: This raise stays outside the except block, so the error does not chain the decoder's error.
    raise IdTokenValidationError(msg)


def _read_task_exception(task: asyncio.Task[None]) -> None:
    """Mark a finished task's exception as retrieved, so asyncio never logs it with its text.

    Args:
        task: The finished task.
    """
    if not task.cancelled():
        task.exception()


def _revocable_tokens(token: Mapping[str, Any], *, label_prefix: str = "") -> list[tuple[str, str]]:
    """Return the tokens a token-endpoint response or one of its members carries.

    Args:
        token: A token-endpoint response, or a member of one that carries a token of its own.
        label_prefix: A word placed before each label, to tell one member's tokens from another's.

    Returns:
        Each token with the kind a log line names it by, the refresh token first.
    """
    return [
        (f"{label_prefix}{label}", value)
        for field, label in (("refresh_token", "refresh token"), ("access_token", "access token"))
        if isinstance(value := token.get(field), str) and value
    ]


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


def _stated_error_member(response: httpx.Response | None) -> object:
    """Return the ``error`` member of a token-endpoint response, as it arrived.

    Args:
        response: The response the endpoint sent, or ``None`` when none was received.

    Returns:
        The member, or an empty string when the response carries no JSON object or no such member.
    """
    if response is None:
        return ""
    try:
        body = decode_json_body(response)
    except ValueError:
        return ""
    return body.get("error", "") if isinstance(body, dict) else ""


def _states_an_access_token(response: Mapping[str, Any]) -> bool:
    """Report whether a token-endpoint response carries the access token RFC 6749 section 5.1 requires.

    Args:
        response: The token-endpoint response to read.

    Returns:
        Whether the response states a non-empty access token.
    """
    return isinstance(access_token := response.get("access_token"), str) and bool(access_token)


def _user_token(nested: Mapping[str, Any]) -> UserToken | None:
    """Return the user token a nested member of a token response carries.

    Args:
        nested: The member the provider issues the authorizing person's token in.

    Returns:
        The token, or ``None`` where the member states no access token.
    """
    access_token = nested.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return None
    # A member is read onto its field only where it holds what that field states. One of any other
    # type is carried as it arrived, because the token beside it is usable either way and a refusal
    # here would lose a token the response issued.
    named: dict[str, Any] = {"access_token": access_token}
    extras: dict[str, Any] = {}
    for member, value in nested.items():
        if member == "access_token":
            continue
        field = _USER_TOKEN_STRINGS.get(member)
        lifetime = finite_number(value) if member in {"expires_at", "expires_in"} else None
        if field is not None and isinstance(value, str):
            named[field] = value
        elif member == "expires_in" and lifetime is not None:
            named["expires_in"] = int(lifetime)
        elif member == "expires_at" and lifetime is not None:
            named["expires_at"] = lifetime
        else:
            extras[member] = value
    named["expires_at"] = _expires_at(named)
    return UserToken(**named, extras=extras)


class OAuthClient:
    """OAuth 2.0 client for authorization code flows, which keeps no per-user state.

    NOTE: Callers must not use one client from event loops in several threads at once,
    because the identity handler it builds may keep caches that are not thread-safe.
    """

    DEFAULT_RETRYABLE_ERROR_CODES = frozenset({SERVER_ERROR, TEMPORARILY_UNAVAILABLE})

    def __init__(
        self,
        config: ProviderConfig,
        state_store: StateStore | None = None,
        revocation_handler: RevocationHandler | None = None,
        identity_handler: IdentityHandler | None = None,
        retryable_error_codes: set[str] | None = None,
        transport_factory: TransportFactory | None = None,
    ) -> None:
        """Create an OAuth client.

        Args:
            config: Provider endpoints, credentials, and behavior.
            state_store: Optional persistence for OAuth state across requests.
            revocation_handler: Optional provider-specific token revocation.
            identity_handler: Optional provider-specific identity fetcher.
            retryable_error_codes: Additional OAuth error codes from the token endpoint that mean
                the same request may succeed later. They merge with, rather than replace,
                ``DEFAULT_RETRYABLE_ERROR_CODES``. Every other code is a rejection of the request as sent.
            transport_factory: Optional factory returning an httpx transport for
                a URL, used for token-endpoint requests. Lets the caller control
                the outbound connection (e.g. pin DNS to validated public IPs)
                when the token endpoint comes from untrusted discovery.
        """
        self._config = config
        self._state_store = state_store
        self._revocation_handler = revocation_handler
        self._identity_handler = identity_handler
        self._retryable_error_codes = self.DEFAULT_RETRYABLE_ERROR_CODES | (retryable_error_codes or set())
        self._transport_factory = transport_factory

    async def get_authorization_url(
        self,
        redirect_uri: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> tuple[str, OAuthPendingState]:
        """Build an authorization URL with state, optional PKCE, and a nonce when the request asks for ``openid``.

        If a ``StateStore`` is configured, the pending state is saved
        automatically before returning.

        Args:
            redirect_uri: Override the redirect URI from ``ProviderConfig``.
            context: Opaque caller context attached to the pending state.

        Returns:
            A tuple of the authorization URL and the pending state.

        Raises:
            ConfigurationError: If no redirect URI is available, or the one in force carries userinfo
                or cannot be read.
                It is also raised when the URI states no ``https`` and names no loopback host, unless
                the config accepts plain HTTP for its redirect URI.
        """
        effective_redirect_uri = redirect_uri or self._config.redirect_uri
        if not effective_redirect_uri:
            msg = "redirect_uri must be provided either in the method call or in ProviderConfig"
            raise ConfigurationError(msg)
        credential = authority_credential(effective_redirect_uri)
        match credential:
            case AuthorityCredential.ABSENT:
                pass
            case AuthorityCredential.MALFORMED:
                msg = "redirect_uri is malformed"
                raise ConfigurationError(msg)
            case AuthorityCredential.PRESENT:
                msg = "redirect_uri must not carry userinfo"
                raise ConfigurationError(msg)
            case _:
                assert_never(credential)
        if not uses_allowed_transport(
            effective_redirect_uri,
            plain_http_allowed=UrlField.REDIRECT_URI in self._config.allow_insecure_http_for,
        ):
            msg = "redirect_uri must use https, or http on a loopback host"
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
            context=context or {},
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
    ) -> FreshTokenSet:
        """Exchange an authorization code for tokens.

        A client with a ``StateStore`` consumes the pending state for ``state`` from it.
        A client without one takes ``pending_state``.
        Either way, a ``state`` that does not match the pending state,
        or a pending state older than the configured maximum age, is refused before the code is redeemed.
        When the authorization request sent a nonce, the response must carry an ID token with that nonce,
        or no tokens are returned.

        When the provider carries an expected issuer, the authorization-response ``iss`` (RFC 9207) is validated first.
        A mix-up attempt is then refused before any state is consumed and before the token endpoint is called.

        NOTE: Callers must keep their own pending state where the user cannot change it,
        because every check here trusts it.
        Callers must also discard it after one exchange attempt, even a failed one,
        because only a ``StateStore`` refuses a pending state that is reused.

        Args:
            code: The authorization code returned to the redirect URI.
            state: The ``state`` parameter from the callback.
            pending_state: The pending state that :meth:`get_authorization_url` returned, when the client has no store.
            iss: The ``iss`` parameter from the authorization response, to
                validate against the provider's expected issuer. Omit when
                the provider has no expected issuer configured.

        Returns:
            The exchanged token set, which identity can be established from.
            Any caller context stored with the pending state is surfaced on :attr:`TokenSet.context`.

        Raises:
            ConfigurationError: If ``pending_state`` is given to a client with a ``StateStore``,
                or is not given to a client without one.
            IdTokenValidationError: If the response carries an ID token that cannot be read, names another
                audience or authorized party, has expired, or names another issuer when the config has one.
                Every ID token the response carries is checked, whether or not the request sent a nonce.
                The response's tokens are revoked first.
            IssuerValidationError: If ``iss`` fails validation against the
                provider's expected issuer.
            NonceValidationError: If the request sent a nonce and the response carries no ID token,
                or an ID token that does not carry that nonce,
                or the pending state of an OpenID request has no nonce, which is refused before the code is redeemed.
                The response's tokens are revoked first when it failed the check against the nonce the request sent.
                A revocation unfinished after 10 seconds is canceled,
                but a revocation handler that does not stop when canceled can delay the error longer.
                At some providers a revocation ends the whole grant, so the user has to authorize again.
            StateError: If the callback carried no state, ``state`` does not match ``pending_state``,
                the store holds no pending state for it because it is invalid, expired, or already consumed,
                or the pending state is older than ``max_pending_age_seconds``,
                carries no usable creation time,
                or was created further ahead of this client's clock than the allowed difference.
            TokenExchangeError: If the token endpoint rejects the exchange, or if its response states no
                access token, which RFC 6749 section 5.1 requires. A response refused for stating none has
                its remaining tokens revoked first, under the same time limit as a refused ID token.
                It does not chain the failed request's error, and its message states nothing the endpoint sent.
        """
        self._config.validate_issuer(iss)
        pending = await self._resolve_pending_state(state, pending_state)
        _check_pending_age(pending, max_age=self._config.max_pending_age_seconds)

        if not pending.nonce and self._requests_openid():
            # NOTE: The code is not redeemed, so no tokens are issued that would need revoking.
            msg = "The pending state has no nonce to check the token response against"
            raise NonceValidationError(msg)

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
            failure = (str(exc), exc.kind, exc.error_code)
        else:
            failure = None
        if failure is not None:
            # NOTE: This raise stays outside the except block and chains nothing, because the internal error's
            # traceback holds the request frame, whose locals carry the grant and the client secret.
            message, kind, error_code = failure
            raise TokenExchangeError(message, kind=kind, error_code=error_code)
        try:
            _check_id_token(
                response.get("id_token"), pending.nonce, client_id=self._config.client_id, issuer=self._config.issuer
            )
        except IdTokenValidationError:
            # NOTE: A response whose ID token fails a check may answer a request the client never made.
            await self._revoke_refused_tokens(response)
            raise
        if not _states_an_access_token(response):
            # The response issued these tokens to this exchange, so nothing else holds them.
            await self._revoke_refused_tokens(response)
            raise TokenExchangeError(_NO_ACCESS_TOKEN_REFUSAL, kind=FailureKind.REFUSED)
        return self._parse_token_response(response, context=pending.context)

    async def _revoke_refused_tokens(self, response: dict[str, Any], *, keep: str | None = None) -> None:
        """Revoke the tokens of a refused token response, where the provider supports revocation.

        Revocation is best effort, and a revocation unfinished at a fixed time limit is canceled.
        Every token the response carries is revoked at once, including one a provider issues inside a
        member of its own.
        A token given as ``keep`` is left alone, for a caller that still holds it and can still use it.
        Each revocation that fails, is canceled on its own, or is unfinished at the limit is logged.
        A log line names the token kind and the host, never error text.
        The error of a revocation unfinished at the limit is not raised.
        If the caller is canceled, the revocations are canceled with it, and nothing is logged.

        NOTE: A revocation handler that ignores cancellation can delay the refusal without bound.

        Args:
            response: The refused token-endpoint response.
            keep: A token the caller presented with the request, which stays valid.

        Raises:
            BaseException: If a revocation that finished before the limit raised an error that is not an exception,
                which revoke_token does not convert.
        """
        tokens = _revocable_tokens(response)
        # A provider can issue a token inside a member of its own, as Slack does under authed_user.
        # The sweep reads the response's shape rather than the config, because a config that names no
        # provider is the one a caller builds by hand and its tokens are no less live.
        for value in response.values():
            if isinstance(value, dict):
                tokens += _revocable_tokens(value, label_prefix="nested ")
        if keep is not None:
            tokens = [(label, token) for label, token in tokens if not _same_secret(token, keep)]
        if not tokens:
            return
        revocation_url = self._config.revocation_url
        if not revocation_url:
            logger.warning(
                "tokens from a refused token response stay valid, because the provider has no revocation endpoint"
            )
            return
        host = urlparse(revocation_url).hostname
        tasks = [asyncio.create_task(self._revoke_one_refused_token(label, token, host)) for label, token in tokens]
        for task in tasks:
            task.add_done_callback(_read_task_exception)
        try:
            _, timed_out = await asyncio.wait(tasks, timeout=_REFUSED_TOKEN_REVOCATION_TIMEOUT_SECONDS)
        finally:
            await _cancel_and_wait(tasks)
        error: BaseException | None = None
        for (label, _), task in zip(tokens, tasks, strict=True):
            if task in timed_out:
                logger.warning(
                    "revoking the %s of a refused token response at %s did not finish within the time limit",
                    label,
                    host,
                )
            elif task.cancelled():
                logger.warning(
                    "the %s of a refused token response could not be revoked at %s (interrupted)", label, host
                )
            elif error is None:
                error = task.exception()
        if error is not None:
            raise error

    async def _revoke_one_refused_token(self, label: str, token: str, host: str | None) -> None:
        """Revoke one token of a refused token response, and log a failure instead of raising it.

        A configuration that cannot revoke is logged like any other failure, because the refusal
        this cleanup follows is what the caller must see.

        Args:
            label: The token's name for the log line, such as ``refresh token``.
            token: The token to revoke.
            host: The revocation endpoint's host, for the log line.
        """
        try:
            await self.revoke_token(token)
        except (ConfigurationError, RevocationError):
            # NOTE: A handler's error text can repeat the token, so the log line must not include it.
            logger.warning("the %s of a refused token response could not be revoked at %s", label, host)

    async def refresh_token(self, refresh_token: str) -> FreshTokenSet:
        """Refresh an access token using a refresh token.

        Args:
            refresh_token: The refresh token to exchange for a new access
                token.

        Returns:
            The refreshed token set, which identity can be established from.

        Raises:
            TokenRefreshError: If the token endpoint refuses the refresh or cannot be reached, or if its
                response states no access token, which RFC 6749 section 5.1 requires. A response refused for
                stating none has every token revoked except ``refresh_token`` itself, which the caller holds.
                Its ``retryable`` says whether the same request may succeed later, and ``error_code``
                tells a dead grant (``invalid_grant``) from a client or configuration problem.
                It does not chain the failed request's error, and its message states nothing the endpoint sent.
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
            failure = (str(exc), exc.kind, exc.error_code)
        else:
            failure = None
        if failure is not None:
            # NOTE: This raise stays outside the except block and chains nothing, because the internal error's
            # traceback holds the request frame, whose locals carry the refresh token and the client secret.
            message, kind, error_code = failure
            raise TokenRefreshError(message, kind=kind, error_code=error_code)
        if not _states_an_access_token(response):
            # A refresh response can repeat the token it was sent, which the caller still holds, so
            # that one token is spared and everything the response issued beside it is revoked.
            await self._revoke_refused_tokens(response, keep=refresh_token)
            raise TokenRefreshError(_NO_ACCESS_TOKEN_REFUSAL, kind=FailureKind.REFUSED)
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
            ConfigurationError: If the provider has no revocation endpoint configured, or if the
                handler refuses the configuration.
                It chains nothing from the handler.
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
            # NOTE: A handler's own error can chain a request that carries the token, and its traceback holds the
            # handler's frames, whose locals carry it too. All three links are dropped.
            exc.__cause__ = None
            exc.__context__ = None
            raise exc.with_traceback(None) from None
        except ConfigurationError as exc:
            # A fault in the configuration keeps its class, because the caller's configuration is its source.
            failure_class, failure_message, failure_kind = ConfigurationError, str(exc), exc.kind
        except OAuthError as exc:
            failure_class, failure_message, failure_kind = RevocationError, str(exc), exc.kind
        except httpx.HTTPError as exc:
            failure = http_failure(exc)
            failure_class = RevocationError
            failure_message, failure_kind = f"Failed to revoke token: {failure.description}", failure.kind
        except Exception:
            failure_class = RevocationError
            failure_message, failure_kind = "Failed to revoke token", FailureKind.UNEXPECTED
        else:
            if not result:
                msg = "Token revocation failed"
                raise RevocationError(msg, kind=FailureKind.REJECTED)
            return True
        # NOTE: The caught error can hold the request, which carries the token, so this error must not reference it.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise failure_class(failure_message, kind=failure_kind)

    async def fetch_identity(self, tokens: FreshTokenSet) -> IdentityProfile:
        """Fetch normalized user identity fields from the provider API.

        Only the :class:`FreshTokenSet` that :meth:`exchange_code` or :meth:`refresh_token` returned is accepted.
        An identity handler may accept the ID token in it without a signature check,
        which is safe only for a token the token endpoint returned over TLS,
        so a token set reloaded from storage is refused.
        The fresh token set is narrowed to an :class:`IdentityMaterial` — exposing only the access token,
        the granted scopes, and, for OIDC providers, the ID token — before being handed to the identity handler,
        so handlers never receive the refresh token or caller context.

        Uses the configured identity handler when provided, otherwise the handler of the provider the config names.
        A config that names no provider, such as a generic OpenID or MCP config, has no handler of its own,
        and neither does one that allows none.
        The configured handler is then the only source of identity.

        Args:
            tokens: The fresh token set to establish identity from.

        Returns:
            The normalized identity profile.

        Raises:
            ConfigurationError: If ``tokens`` is not a fresh token set, if no handler is configured
                and either of the config's OAuth endpoints is not a host of the provider it names, or
                if the handler refuses the configuration.
                It chains nothing from the handler.
            IdentityNotSupportedError: If no identity handler is configured, and the config names no
                provider or allows no handler of its own.
            IdentityFetchError: If the handler fails to fetch identity.
                It chains nothing from the handler.
            TypeError: If the named provider states a class that does not fetch identity, which is a
                defect in this library rather than in the config.
        """
        if not isinstance(tokens, FreshTokenSet):
            msg = (
                "Identity needs the token set that the code exchange or refresh returned. "
                "A token set reloaded from storage cannot be used for identity."
            )
            raise ConfigurationError(msg)
        configured = self._identity_handler
        handler = configured if configured is not None else self._provider_identity_handler
        if handler is None:
            msg = "No identity handler is available for this provider configuration"
            raise IdentityNotSupportedError(msg)
        material = IdentityMaterial.from_token_set(tokens)
        try:
            return await handler.fetch_identity(material, self._config)
        except IdentityFetchError as exc:
            # NOTE: A handler's own error can chain a request that carries the token, and its traceback holds the
            # handler's frames, whose locals carry it too. All three links are dropped.
            exc.__cause__ = None
            exc.__context__ = None
            raise exc.with_traceback(None) from None
        except ConfigurationError as exc:
            # A fault in the configuration keeps its class, because the caller's configuration is its source.
            failure_class, failure_message, failure_kind = ConfigurationError, str(exc), exc.kind
        except OAuthError as exc:
            failure_class, failure_message, failure_kind = IdentityFetchError, str(exc), exc.kind
        except httpx.HTTPError as exc:
            failure = http_failure(exc)
            failure_class = IdentityFetchError
            failure_message, failure_kind = f"Failed to fetch identity: {failure.description}", failure.kind
        except Exception:
            failure_class = IdentityFetchError
            failure_message, failure_kind = "Failed to fetch identity", FailureKind.UNEXPECTED
        # NOTE: The caught error can hold the request, which carries the token, so this error must not reference it.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise failure_class(failure_message, kind=failure_kind)

    @cached_property
    def _provider_identity_handler(self) -> IdentityHandler | None:
        """Return the identity handler of the provider this config names, building it on first use.

        Keeping one handler lets its caches, such as an issuer's signing keys, serve every sign-in.

        Returns:
            The named provider's handler, or ``None`` when the config names no provider or allows
            no handler of its own.

        Raises:
            ConfigurationError: If either of the config's OAuth endpoints is not a host of the
                provider it names.
        """
        return identity_handler_for(self._config)

    def _authorization_query(self, params: dict[str, str]) -> dict[str, str | list[str]]:
        """Return the query of an authorization URL that sends ``params``.

        Args:
            params: The request parameters this client sets.

        Returns:
            The query, with each parameter's value or values.
        """
        return authorization_query(self._config, params)

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
        return scope_param(self._config)

    def _sends_openid(self, query: Mapping[str, str | list[str]]) -> bool:
        """Return whether an authorization query asks for the ``openid`` scope.

        Args:
            query: The query of an authorization URL.

        Returns:
            ``True`` when a scope word in ``query`` is ``openid``.
        """
        return "openid" in sent_scope_words(query, "scope", self._config.scope_separator)

    def _sent_secrets(self, sent: dict[str, str]) -> frozenset[str]:
        """Return the secret values a token request sends, which are the client secret and the grant's own.

        Args:
            sent: The form fields the request sent.

        Returns:
            The values, without any the request left empty.
        """
        values = {sent[field] for field in _SENT_SECRET_FIELDS if field in sent}
        if self._config.client_secret is not None:
            values.add(self._config.client_secret.get_secret_value())
        return frozenset(value for value in values if value)

    def _stated_error_code(self, response: httpx.Response | None, sent: dict[str, str]) -> str:
        """Return the error code a token response states, or an empty string when it states none to report.

        A value the request sent as a secret is not reported.
        An endpoint may echo what it was sent, and a secret can take the shape a code takes.

        Args:
            response: The response the endpoint sent, or ``None`` when none was received.
            sent: The form fields the request sent.

        Returns:
            The error code, or an empty string.
        """
        code = recognized_error_code(_stated_error_member(response))
        return "" if code in self._sent_secrets(sent) else code

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
                when the endpoint states one that this request did not send as a secret.
                The caught error is not attached as its cause or context.
                Its message is this library's own text and states nothing the endpoint sent.
        """
        from authlib.integrations.base_client.errors import OAuthError as AuthlibOAuthError
        from authlib.integrations.httpx_client import AsyncOAuth2Client

        # The token client reports an OAuth error body without the response it came from, so it is recorded here.
        responses: list[httpx.Response] = []

        async def record_response(response: httpx.Response) -> None:
            responses.append(response)

        try:
            client_secret = self._config.client_secret
            transport = self._transport_factory(self._config.token_url) if self._transport_factory is not None else None
            async with AsyncOAuth2Client(
                client_id=self._config.client_id,
                client_secret=client_secret.get_secret_value() if client_secret is not None else None,
                token_endpoint_auth_method=self._config.token_endpoint_auth_method,
                transport=transport,
                event_hooks={"response": [record_response]},
            ) as client:
                token = await client.fetch_token(self._config.token_url, **data)
            return dict(token)
        except AuthlibOAuthError:
            # A response with an OAuth error body, which an endpoint may send with any status.
            response = responses[-1] if responses else None
            error_code = self._stated_error_code(response, data)
            status_code = response.status_code if response is not None else None
            kind = self._kind_for_token_response(status_code, error_code)
            if status_code is not None and httpx.codes.is_error(status_code):
                description = status_failure(status_code).description
            else:
                # An error body can arrive with a status that describes no failure of its own.
                description = "token endpoint returned an error"
            failure = _TokenEndpointError(description, kind, error_code=error_code)
        except httpx.HTTPStatusError as exc:
            # An error status without an OAuth error body that the token client recognized.
            # The body may still carry an OAuth error code, which then decides the kind.
            error_code = self._stated_error_code(exc.response, data)
            kind = self._kind_for_token_response(exc.response.status_code, error_code)
            status = status_failure(exc.response.status_code)
            failure = _TokenEndpointError(status.description, kind, error_code=error_code)
        except httpx.RequestError as exc:
            transport = http_failure(exc)
            failure = _TokenEndpointError(transport.description, transport.kind)
        # NOTE: The token client decodes a success body itself, so a deeply nested body surfaces here as RecursionError.
        except (json.JSONDecodeError, RecursionError):
            failure = _TokenEndpointError("token response could not be read", FailureKind.REFUSED)
        except Exception:
            failure = _TokenEndpointError("request failed", FailureKind.UNEXPECTED)
        # NOTE: The caught error can hold the request, which carries the client secret and the grant.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise failure

    def _kind_for_token_response(self, status: int | None, error_code: str) -> FailureKind:
        """Return the kind of a failed token-endpoint response.

        A server error or a rate limit status is retryable whatever code the body carries.
        Otherwise the code decides. RFC 6749 section 5.2 defines every token-endpoint code as a fault
        in the request as sent, so only a code in the retryable set, such as ``temporarily_unavailable``,
        may pass later.

        Args:
            status: The response status, or ``None`` when it is not known.
            error_code: The error code the response stated, or an empty string when it stated none
                in the shape a code takes.

        Returns:
            The kind.
        """
        status_kind = status_failure(status).kind if status is not None else None
        if status_kind is FailureKind.SERVER_ERROR or not error_code:
            return FailureKind.REJECTED if status_kind is None else status_kind
        return FailureKind.SERVER_ERROR if error_code in self._retryable_error_codes else FailureKind.REJECTED

    def _parse_token_response(self, data: dict, context: dict[str, Any] | None = None) -> FreshTokenSet:
        """Parse a token endpoint response into a fresh token set.

        Args:
            data: A token-endpoint response.
            context: Caller context to carry onto :attr:`TokenSet.context`;
                treated as empty when ``None``.

        Returns:
            The parsed token set. Response fields with no named slot are
            collected into :attr:`TokenSet.extras`, including one whose value is
            not of the type its own field states, and ``expires_at`` is
            derived from ``expires_in`` when the response omits it.
            A token the provider issues for the authorizing person is read onto
            :attr:`TokenSet.user_token` and kept out of the extras.
        """
        known_fields = {"access_token", *_TOKEN_SET_NUMBERS, *_TOKEN_SET_STRINGS}
        extras = {k: v for k, v in data.items() if k not in known_fields}

        # A field is read onto its attribute only where it holds what that attribute states. One of any
        # other type is carried into the extras, because the access token is usable either way and a
        # refusal here would strand a token the response issued.
        named: dict[str, Any] = {}
        for field in _TOKEN_SET_STRINGS:
            value = data.get(field)
            if value is None:
                continue
            if isinstance(value, str):
                named[field] = value
            else:
                extras[field] = value
        for field in _TOKEN_SET_NUMBERS:
            value = data.get(field)
            if value is None:
                continue
            number = finite_number(value)
            if number is None:
                extras[field] = value
            else:
                named[field] = int(number) if field == "expires_in" else number

        # A token left in the extras is a token no caller names, so nothing refreshes or revokes it.
        user_token = None
        nested_field = self._config.provider.user_token_response_field if self._config.provider else None
        if nested_field is not None and isinstance(nested := extras.get(nested_field), dict):
            user_token = _user_token(nested)
            if user_token is not None:
                del extras[nested_field]

        named["expires_at"] = _expires_at(named)

        return FreshTokenSet(
            access_token=data["access_token"],
            user_token=user_token,
            extras=extras,
            context=context or {},
            **named,
        )
