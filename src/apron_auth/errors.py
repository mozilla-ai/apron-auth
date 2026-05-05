"""Exception hierarchy for apron-auth OAuth operations."""

from __future__ import annotations


class OAuthError(Exception):
    """Base exception for all apron-auth errors."""


class ConfigurationError(OAuthError):
    """Provider configuration is invalid or incomplete."""


class IdentityFetchError(OAuthError):
    """Fetching user identity from the provider failed."""


class IdentityNotSupportedError(OAuthError):
    """Identity fetching is not supported for this provider configuration."""


class PermanentOAuthError(OAuthError):
    """Irrecoverable OAuth failure.

    Raised for errors like invalid_grant, unauthorized_client, or
    invalid_client. The caller should delete the stored token.
    """


class RevocationError(OAuthError):
    """Token revocation failed at the provider."""


class StateError(OAuthError):
    """OAuth state invalid, expired, or already consumed."""


class TokenExchangeError(OAuthError):
    """Authorization code exchange failed."""


class TokenRefreshError(OAuthError):
    """Token refresh failed (transient — retry may succeed)."""
