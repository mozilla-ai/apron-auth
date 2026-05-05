"""Stateless OAuth 2.0 protocol library."""

from __future__ import annotations

from apron_auth.client import OAuthClient
from apron_auth.errors import (
    ConfigurationError,
    IdentityFetchError,
    IdentityNotSupportedError,
    OAuthError,
    PermanentOAuthError,
    RevocationError,
    StateError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import IdentityProfile, OAuthPendingState, ProviderConfig, ScopeMetadata, TokenSet
from apron_auth.protocols import IdentityHandler, RevocationHandler, StandardRevocationHandler, StateStore
from apron_auth.stores import MemoryStateStore

__all__ = [
    "ConfigurationError",
    "IdentityFetchError",
    "IdentityHandler",
    "IdentityNotSupportedError",
    "IdentityProfile",
    "MemoryStateStore",
    "OAuthClient",
    "OAuthError",
    "OAuthPendingState",
    "PermanentOAuthError",
    "ProviderConfig",
    "RevocationError",
    "RevocationHandler",
    "ScopeMetadata",
    "StandardRevocationHandler",
    "StateError",
    "StateStore",
    "TokenExchangeError",
    "TokenRefreshError",
    "TokenSet",
]
