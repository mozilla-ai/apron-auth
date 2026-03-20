"""Protocols for caller-provided storage and provider-specific revocation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

import httpx

if TYPE_CHECKING:
    from apron_auth.models import OAuthPendingState, ProviderConfig


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


class StandardRevocationHandler:
    """RFC 7009 token revocation via POST with token in form body."""

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token using standard RFC 7009 POST."""
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.revocation_url,
                data={"token": token},
                auth=(config.client_id, config.client_secret.get_secret_value()),
            )
        return response.is_success
