"""Protocols for caller-provided storage and provider-specific revocation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

import httpx

from apron_auth.errors import RevocationError

if TYPE_CHECKING:
    from apron_auth.models import IdentityProfile, OAuthPendingState, ProviderConfig


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

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using the provider API."""
        ...


class StandardRevocationHandler:
    """RFC 7009 token revocation via POST with token in form body."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token using standard RFC 7009 POST."""
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
        revocation_url = config.revocation_url
        if self._client is not None:
            return await self._send(self._client, token, revocation_url, config)
        async with httpx.AsyncClient() as client:
            return await self._send(client, token, revocation_url, config)

    async def _send(
        self,
        client: httpx.AsyncClient,
        token: str,
        revocation_url: str,
        config: ProviderConfig,
    ) -> bool:
        """Send the revocation request and return success status."""
        try:
            response = await client.post(
                revocation_url,
                data={"token": token},
                auth=(config.client_id, config.client_secret.get_secret_value()),
            )
        except httpx.RequestError as exc:
            raise RevocationError(str(exc)) from exc
        return response.is_success
