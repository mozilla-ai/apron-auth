"""Stateless OAuth 2.0 protocol library."""

from __future__ import annotations

import logging

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
from apron_auth.models import (
    IdentityMaterial,
    IdentityProfile,
    OAuthPendingState,
    ProviderConfig,
    ScopeMetadata,
    TenancyContext,
    TokenSet,
)
from apron_auth.protocols import IdentityHandler, RevocationHandler, StandardRevocationHandler, StateStore
from apron_auth.stores import MemoryStateStore

# Keep the library silent until the application opts in. Without a
# handler anywhere on the chain, ``logging.lastResort`` writes records of
# WARNING and above to the consumer's stderr — output a library has no
# standing to emit uninvited. Configuring the ``apron_auth`` logger in
# any way replaces this.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "ConfigurationError",
    "IdentityFetchError",
    "IdentityHandler",
    "IdentityMaterial",
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
    "TenancyContext",
    "TokenExchangeError",
    "TokenRefreshError",
    "TokenSet",
]
