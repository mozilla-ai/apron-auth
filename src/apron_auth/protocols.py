"""Protocols for caller-provided storage and provider-specific revocation."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import httpx

from apron_auth._http_errors import http_failure, status_failure
from apron_auth.errors import ConfigurationError, RevocationError

if TYPE_CHECKING:
    from apron_auth.models import IdentityMaterial, IdentityProfile, OAuthPendingState, ProviderConfig


TransportFactory = Callable[[str], httpx.AsyncBaseTransport]
"""Caller factory returning an httpx transport for a given URL.

Lets a caller control the outbound connection for a URL — for example to pin
DNS resolution to validated public addresses and prevent SSRF via rebinding.
"""


@runtime_checkable
class StateStore(Protocol):
    """Caller provides persistence for OAuth state.

    NOTE: Implementations must return every field of a saved pending state, including ``created_at`` and ``nonce``.
    An implementation that rebuilds the state from a stored record must pass the model's own fields alone.
    A field the model does not define is refused rather than ignored, so a record carrying keys of the store's
    own, such as a document identifier or an expiry attribute, needs those keys left out.

    Enforcing a maximum age is not part of this contract.
    An implementation may still expire stale entries to bound its storage.

    See MemoryStateStore for a reference implementation with automatic expiry.
    """

    async def save(self, state: OAuthPendingState) -> None:
        """Store pending state during authorization URL generation.

        Args:
            state: The pending state to store.
        """
        ...

    async def consume(self, state_key: str) -> OAuthPendingState | None:
        """Atomically retrieve and invalidate state.

        Args:
            state_key: The state token to look up and invalidate.

        Returns:
            The stored state, or ``None`` if it is invalid, expired, or
            already consumed.
        """
        ...


@runtime_checkable
class RevocationHandler(Protocol):
    """Provider-specific token revocation."""

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token at the provider.

        NOTE: Implementations must keep credentials out of a raised error's message and attributes.
        A raised error's cause and context are discarded.
        An error that is not one of this library's errors is replaced by a fixed message.

        Args:
            token: The token to revoke.
            config: The provider configuration to revoke against.

        Returns:
            ``True`` if revocation succeeded.

        Raises:
            ConfigurationError: If the configuration cannot be used to revoke.
                A caller's configuration is the source of that fault, so it is not a revocation
                failure.
            RevocationError: If the request cannot be sent or the provider refuses it.
                Implementations should pass ``kind``, because only they know whether the provider
                was unreachable, answered a server error, or rejected the request.
                An error raised without one is ``UNEXPECTED`` and never retried.
        """
        ...


@runtime_checkable
class IdentityHandler(Protocol):
    """Provider-specific identity retrieval."""

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using the provider API.

        NOTE: Implementations must keep credentials out of a raised error's message and attributes.
        A raised error's cause and context are discarded.
        An error that is not one of this library's errors is replaced by a fixed message.

        NOTE: An implementation that derives the endpoint it sends the access token to must derive it
        from ``config.authorize_url`` or ``config.token_url``.
        No other field of a configuration is checked against the hosts of the provider it names.

        Args:
            material: The token material to establish identity from.
            config: The provider configuration the tokens were issued under.

        Returns:
            The normalized identity profile.

        Raises:
            IdentityFetchError: If the identity cannot be fetched or the response does not validate.
                Implementations should pass ``kind``, because only they know whether the provider
                was unreachable, answered a server error, rejected the token, or sent an invalid response.
                An error raised without one is ``UNEXPECTED`` and never retried.
                ``IdentityScopeNotGrantedError`` reports a token that lacks a scope the endpoint needs.
            ConfigurationError: If the configuration cannot be used for an identity request,
                including a refusal of the endpoints it carries.
                A caller's configuration is the source of that fault, so it is not an identity
                fetch failure.
        """
        ...


class StandardRevocationHandler:
    """RFC 7009 token revocation via POST with token in form body."""

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        transport_factory: TransportFactory | None = None,
    ) -> None:
        """Configure how revocation requests reach the network.

        Args:
            client: A caller-owned client to send every revocation through;
                when supplied, ``transport_factory`` is unused.
            transport_factory: Factory controlling the outbound connection for
                the revocation URL when no ``client`` is given. The URL is
                server-supplied, so a caller handling untrusted input can pin
                DNS to validated addresses here to prevent SSRF via rebinding.
        """
        self._client = client
        self._transport_factory = transport_factory

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token using standard RFC 7009 POST.

        Args:
            token: The token to revoke.
            config: The provider configuration; its ``revocation_url`` and
                client credentials are used for the request.

        Returns:
            ``True`` when the endpoint reports success.

        Raises:
            ConfigurationError: If ``config`` has no revocation URL.
            RevocationError: If the request fails to reach the endpoint.
                The failed request's error is not attached as its cause or context.
        """
        if config.revocation_url is None:
            msg = "the provider configuration carries no revocation endpoint"
            raise ConfigurationError(msg)
        revocation_url = config.revocation_url
        if self._client is not None:
            return await self._send(self._client, token, revocation_url, config)
        transport = self._transport_factory(revocation_url) if self._transport_factory is not None else None
        async with httpx.AsyncClient(transport=transport) as client:
            return await self._send(client, token, revocation_url, config)

    async def _send(
        self,
        client: httpx.AsyncClient,
        token: str,
        revocation_url: str,
        config: ProviderConfig,
    ) -> bool:
        """Send the revocation request and return success status.

        A public client carries no secret, so no HTTP Basic credential is
        attached in that case.

        Args:
            client: The HTTP client to send the request through.
            token: The token to revoke.
            revocation_url: The endpoint to POST the revocation to.
            config: The provider configuration supplying client credentials.

        Returns:
            ``True`` when the endpoint responds with success.

        Raises:
            RevocationError: If the request fails to reach the endpoint, or the endpoint answers an error status.
                Its kind says whether the endpoint may accept the request later.
                The failed request's error is not attached as its cause or context.
        """
        auth = config.basic_auth()
        data = {"token": token}
        if auth is None:
            # RFC 7009 section 5: a public client identifies itself with
            # client_id in the request body, presenting no client authentication.
            data["client_id"] = config.client_id
        try:
            response = await client.post(
                revocation_url,
                data=data,
                # Pass None for a public client, so an injected HTTP client's own auth
                # flow is not applied to the server-supplied revocation URL. The HTTP
                # client accepts None at runtime, and only its type stub omits it.
                auth=auth,  # ty: ignore[invalid-argument-type]
            )
        except httpx.RequestError as exc:
            failure = http_failure(exc)
        else:
            if response.is_success:
                return True
            failure = status_failure(response.status_code)
        # NOTE: The caught error holds the request, which carries the token, so this error must not reference it.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise RevocationError(f"Failed to revoke token: {failure.description}", kind=failure.kind)
