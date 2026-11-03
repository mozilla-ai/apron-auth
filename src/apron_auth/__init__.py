"""Stateless OAuth 2.0 protocol library."""

from __future__ import annotations

import logging

from apron_auth.client import OAuthClient, StoredStateClient
from apron_auth.errors import (
    INVALID_CLIENT,
    INVALID_GRANT,
    SERVER_ERROR,
    TEMPORARILY_UNAVAILABLE,
    UNAUTHORIZED_CLIENT,
    AuthorizationResponseError,
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
    AuthorizationCallback,
    BrowserBoundAuthorization,
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
    TimeoutPolicy,
    TokenEndpointAuthMethod,
    TokenSet,
    UrlField,
    UserToken,
    WorkloadIssuer,
)
from apron_auth.protocols import IdentityHandler, RevocationHandler, StateStore
from apron_auth.providers._revocation import StandardRevocationHandler
from apron_auth.stores import MemoryStateStore

# Keep the library silent until the application opts in. Without a
# handler anywhere on the chain, ``logging.lastResort`` writes records of
# WARNING and above to the consumer's stderr — output a library has no
# standing to emit uninvited. Configuring the ``apron_auth`` logger in
# any way replaces this.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "ApplicationType",
    "AuthorizationCallback",
    "AuthorizationResponseError",
    "BrowserBoundAuthorization",
    "ClientRegistration",
    "ConfigurationError",
    "FailureKind",
    "FreshTokenSet",
    "INVALID_CLIENT",
    "INVALID_GRANT",
    "IdTokenValidationError",
    "IdentityFetchError",
    "IdentityHandler",
    "IdentityMaterial",
    "IdentityNotSupportedError",
    "IdentityProfile",
    "IdentityScopeNotGrantedError",
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
    "StoredStateClient",
    "TEMPORARILY_UNAVAILABLE",
    "TenancyContext",
    "TimeoutPolicy",
    "TokenEndpointAuthMethod",
    "TokenEndpointError",
    "TokenExchangeError",
    "TokenRefreshError",
    "TokenSet",
    "UNAUTHORIZED_CLIENT",
    "UrlField",
    "UserToken",
    "WorkloadIssuer",
]
