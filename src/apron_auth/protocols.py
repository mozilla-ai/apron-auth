"""Protocols for caller-provided storage and provider-specific revocation."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import httpx

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

        NOTE: Implementations must keep credentials out of a raised error's message and attributes,
        and must not chain an error that carries them.

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

        NOTE: Implementations must keep credentials out of a raised error's message and attributes,
        and must not chain an error that carries them.

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
