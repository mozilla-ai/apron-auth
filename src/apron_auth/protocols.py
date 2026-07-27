"""Protocols for caller-provided storage and provider-specific revocation."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import httpx

from apron_auth.errors import RevocationError

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

    Implementations are responsible for expiring stale entries.
    Each OAuthPendingState carries a created_at timestamp that
    implementations should use to enforce a maximum age (typically
    under 10 minutes for OAuth authorization flows).

    See MemoryStateStore for a reference implementation with
    automatic expiry.
    """

    async def save(self, state: OAuthPendingState) -> None:
        """Store pending state during authorization URL generation."""
        ...

    async def consume(self, state_key: str) -> OAuthPendingState | None:
        """Atomically retrieve and invalidate state.

        Returns None if the state is invalid, expired, or already consumed.
        """
        ...


@runtime_checkable
class RevocationHandler(Protocol):
    """Provider-specific token revocation."""

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token at the provider.

        Returns True if revocation succeeded.
        """
        ...


@runtime_checkable
class IdentityHandler(Protocol):
    """Provider-specific identity retrieval."""

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using the provider API."""
        ...


@runtime_checkable
class IdentityResolver(Protocol):
    """Provider-specific identity-handler resolver."""

    def __call__(self, config: ProviderConfig) -> IdentityHandler | None:
        """Return an identity handler when config matches this provider."""
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
        """Revoke a token using standard RFC 7009 POST."""
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
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
                # Pass None (not USE_CLIENT_DEFAULT) for a public client so an
                # injected client's default auth is never sent to the
                # server-supplied revocation URL. httpx accepts None at runtime;
                # its AuthTypes stub omits it, hence the narrow ignore.
                auth=auth,  # ty: ignore[invalid-argument-type]
            )
        except httpx.RequestError as exc:
            raise RevocationError(str(exc)) from exc
        return response.is_success
