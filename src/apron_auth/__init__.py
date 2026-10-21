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
    FailureKind,
    IdentityFetchError,
    IdentityNotSupportedError,
    IdentityScopeNotGrantedError,
    IdTokenValidationError,
    IssuerValidationError,
    McpDiscoveryError,
    McpRegistrationError,
    NonceValidationError,
    OAuthError,
    OidcDiscoveryError,
    RevocationError,
    StateError,
    TokenEndpointError,
    TokenExchangeError,
    TokenRefreshError,
)
from apron_auth.models import (
    ApplicationType,
    ClientRegistration,
    FreshTokenSet,
    IdentityMaterial,
    IdentityProfile,
    OAuthPendingState,
    Provider,
    ProviderConfig,
    ScopeMetadata,
    ServerMetadata,
    TenancyContext,
    TokenEndpointAuthMethod,
    TokenSet,
    UrlField,
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
    "ApplicationType",
    "ClientRegistration",
    "ConfigurationError",
    "FailureKind",
    "FreshTokenSet",
    "IdentityFetchError",
    "IdentityHandler",
    "IdentityMaterial",
    "INVALID_CLIENT",
    "INVALID_GRANT",
    "IdentityNotSupportedError",
    "IdentityProfile",
    "IdentityScopeNotGrantedError",
    "IdTokenValidationError",
    "IssuerValidationError",
    "McpDiscoveryError",
    "McpRegistrationError",
    "MemoryStateStore",
    "NonceValidationError",
    "OAuthClient",
    "OAuthError",
    "OAuthPendingState",
    "OidcDiscoveryError",
    "Provider",
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
    "TokenEndpointError",
    "TokenExchangeError",
    "TokenRefreshError",
    "TokenSet",
    "UNAUTHORIZED_CLIENT",
    "UrlField",
]
