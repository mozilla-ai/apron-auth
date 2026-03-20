"""Stateless OAuth 2.0 protocol library."""

from __future__ import annotations

from apron_auth.client import OAuthClient
from apron_auth.errors import (
    ConfigurationError,
    OAuthError,
    PermanentOAuthError,
    RevocationError,
    StateError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import OAuthPendingState, ProviderConfig, TokenSet
from apron_auth.protocols import RevocationHandler, StandardRevocationHandler, StateStore
from apron_auth.stores import MemoryStateStore

__all__ = [
    "ConfigurationError",
    "MemoryStateStore",
    "OAuthClient",
    "OAuthError",
    "OAuthPendingState",
    "PermanentOAuthError",
    "ProviderConfig",
    "RevocationError",
    "RevocationHandler",
    "StandardRevocationHandler",
    "StateError",
    "StateStore",
    "TokenExchangeError",
    "TokenRefreshError",
    "TokenSet",
]
