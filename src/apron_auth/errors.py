"""Exception hierarchy for apron-auth OAuth operations."""

from __future__ import annotations

# Well-known OAuth 2.0 error codes (RFC 6749 §5.2 and §4.1.2.1) seen in
# token-endpoint responses. ``error_code`` is a plain ``str`` because a provider
# may return codes outside this set; these names let callers and this library
# compare against the common values without bare string literals.
INVALID_GRANT = "invalid_grant"
INVALID_CLIENT = "invalid_client"
UNAUTHORIZED_CLIENT = "unauthorized_client"
SERVER_ERROR = "server_error"
TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"


class OAuthError(Exception):
    """Base exception for all apron-auth errors.

    ``error_code`` holds the OAuth error code (RFC 6749) for failures that carry one, and is the empty string otherwise.
    """

    def __init__(self, *args: object, error_code: str = "") -> None:
        super().__init__(*args)
        self.error_code = error_code


class ConfigurationError(OAuthError):
    """Provider configuration is invalid or incomplete."""


class IdentityFetchError(OAuthError):
    """Fetching user identity from the provider failed."""


class IdentityNotSupportedError(OAuthError):
    """Identity fetching is not supported for this provider configuration."""


class McpDiscoveryError(OAuthError):
    """MCP OAuth metadata discovery failed."""


class McpRegistrationError(OAuthError):
    """MCP OAuth dynamic client registration failed."""


class PermanentOAuthError(OAuthError):
    """Token-endpoint rejection that retrying the identical request will not resolve.

    Raised for OAuth error codes such as ``invalid_grant``, ``invalid_client``, and ``unauthorized_client``.
    It asserts only that the request will not succeed on retry as sent;
    it does not assert that stored credentials should be discarded.
    Read ``error_code`` to distinguish a dead grant (``invalid_grant``) from a client or configuration problem.
    """


class RevocationError(OAuthError):
    """Token revocation failed at the provider."""


class StateError(OAuthError):
    """OAuth state invalid, expired, or already consumed."""


class TokenExchangeError(OAuthError):
    """Authorization code exchange failed."""


class TokenRefreshError(OAuthError):
    """Token refresh failed; the failure is transient and retrying may succeed.

    ``error_code`` carries the OAuth error code when the provider supplied one, and is empty for network-level failures.
    """
