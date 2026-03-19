"""Exception hierarchy for any-auth OAuth operations."""

from __future__ import annotations


class OAuthError(Exception):
    """Base exception for all any-auth errors."""


class TokenExchangeError(OAuthError):
    """Authorization code exchange failed."""


class TokenRefreshError(OAuthError):
    """Token refresh failed (transient — retry may succeed)."""


class PermanentOAuthError(OAuthError):
    """Irrecoverable OAuth failure.

    Raised for errors like invalid_grant, unauthorized_client, or
    invalid_client. The caller should delete the stored token.
    """


class RevocationError(OAuthError):
    """Token revocation failed at the provider."""


class StateError(OAuthError):
    """OAuth state invalid, expired, or already consumed."""


class ConfigurationError(OAuthError):
    """Provider configuration is invalid or incomplete."""
