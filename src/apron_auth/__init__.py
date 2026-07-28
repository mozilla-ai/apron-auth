"""Stateless OAuth 2.0 protocol library."""

from __future__ import annotations

import logging

from apron_auth.client import OAuthClient
from apron_auth.errors import (
    INVALID_CLIENT,
    INVALID_GRANT,
    SERVER_ERROR,
    TEMPORARILY_UNAVAILABLE,
    UNAUTHORIZED_CLIENT,
    ConfigurationError,
    IdentityFetchError,
    IdentityNotSupportedError,
    McpDiscoveryError,
    McpRegistrationError,
    OAuthError,
    PermanentOAuthError,
    RevocationError,
    StateError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import (
    ClientRegistration,
    IdentityMaterial,
    IdentityProfile,
    OAuthPendingState,
    ProviderConfig,
    ScopeMetadata,
    ServerMetadata,
    TenancyContext,
    TokenEndpointAuthMethod,
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
    "ClientRegistration",
    "ConfigurationError",
    "IdentityFetchError",
    "IdentityHandler",
    "IdentityMaterial",
    "INVALID_CLIENT",
    "INVALID_GRANT",
    "IdentityNotSupportedError",
    "IdentityProfile",
    "McpDiscoveryError",
    "McpRegistrationError",
    "MemoryStateStore",
    "OAuthClient",
    "OAuthError",
    "OAuthPendingState",
    "PermanentOAuthError",
    "ProviderConfig",
    "RevocationError",
    "RevocationHandler",
    "SERVER_ERROR",
    "ScopeMetadata",
    "ServerMetadata",
    "StandardRevocationHandler",
    "StateError",
    "StateStore",
    "TEMPORARILY_UNAVAILABLE",
    "TenancyContext",
    "TokenEndpointAuthMethod",
    "TokenExchangeError",
    "TokenRefreshError",
    "TokenSet",
    "UNAUTHORIZED_CLIENT",
]
