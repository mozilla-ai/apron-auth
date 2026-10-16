"""Exception hierarchy for apron-auth OAuth operations."""

from __future__ import annotations

# Well-known OAuth 2.0 error codes (RFC 6749 §5.2 and §4.1.2.1) seen in
# token-endpoint responses. ``error_code`` is a plain ``str`` because a provider
# may return codes outside this set; these names let callers and this library
# compare against the common values without bare string literals.
INVALID_CLIENT = "invalid_client"
INVALID_GRANT = "invalid_grant"
SERVER_ERROR = "server_error"
TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
UNAUTHORIZED_CLIENT = "unauthorized_client"


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
    """Fetching user identity from the provider failed.

    The failure may be transient, so retrying may succeed.
    """


class IdentityNotSupportedError(OAuthError):
    """Identity fetching is not supported for this provider configuration."""


class IdentityScopeNotGrantedError(IdentityFetchError):
    """The token is known to lack a scope the provider's identity endpoint requires.

    Retrying with the same token cannot succeed.
    The caller must obtain a token that carries the required scope.
    """


class IssuerValidationError(OAuthError):
    """Authorization-response issuer (RFC 9207) did not match the expected issuer.

    Raised when a code exchange is refused because the authorization response's
    ``iss`` parameter is absent where required or names a different authorization
    server than the one the flow was configured for — the signature of an
    authorization-server mix-up.
    """


class McpDiscoveryError(OAuthError):
    """MCP OAuth metadata discovery failed."""


class McpRegistrationError(OAuthError):
    """MCP OAuth dynamic client registration failed."""


class OidcDiscoveryError(OAuthError):
    """Reading an OpenID provider's configuration document failed.

    It is raised when a URL is refused, or the document cannot be fetched or parsed.
    It is also raised when the document omits a required endpoint or names another issuer.
    An issuer mismatch is a refusal, not a transport failure.
    OpenID Connect Discovery 1.0 section 4.3 requires the document to name the issuer it was fetched for.
    """


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
    """The OAuth state from a callback is missing, invalid, expired, already consumed, or not the pending state's."""


class TokenExchangeError(OAuthError):
    """Authorization code exchange failed: the token endpoint refused the code, or this client refused its response."""


# NonceValidationError follows its base class instead of A-Z order, because Python needs the base defined first.
class NonceValidationError(TokenExchangeError):
    """A code exchange is not shown to answer the authorization request whose nonce it should carry.

    The response may carry no ID token, or one with no nonce or a different one, or one that cannot be read.
    The pending state of an OpenID request may also have lost its nonce, so there is nothing to compare.
    The token response may answer an authorization request this client did not start.
    """


class TokenRefreshError(OAuthError):
    """Token refresh failed; the failure is transient and retrying may succeed.

    ``error_code`` carries the OAuth error code when the provider supplied one, and is empty for network-level failures.
    """


# TokenVerificationError and TokenExpiredError follow their base classes instead of A-Z order, as above.
class TokenVerificationError(IdentityFetchError):
    """A signed token was refused: it is malformed, no published key verifies it, or its claims do not validate.

    Retrying the same token cannot succeed.
    A failure to fetch the issuer's signing keys is not a refusal, and raises the base class instead.
    """


class TokenExpiredError(TokenVerificationError):
    """A signed token verified but has expired, so the caller must obtain a fresh one."""
