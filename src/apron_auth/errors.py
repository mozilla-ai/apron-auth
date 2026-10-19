"""Exception hierarchy for apron-auth OAuth operations.

Every error is organized on two axes.
The class says which step failed: the code exchange, a refresh, a revocation, an identity fetch, or a discovery.
The ``kind`` says what went wrong in a way a caller can act on, and ``retryable`` follows from it.
"""

from __future__ import annotations

from enum import StrEnum

# Well-known OAuth 2.0 error codes (RFC 6749 §5.2 and §4.1.2.1) seen in
# token-endpoint responses. ``error_code`` is a plain ``str`` because a provider
# may return codes outside this set; these names let callers and this library
# compare against the common values without bare string literals.
INVALID_CLIENT = "invalid_client"
INVALID_GRANT = "invalid_grant"
SERVER_ERROR = "server_error"
TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
UNAUTHORIZED_CLIENT = "unauthorized_client"


class FailureKind(StrEnum):
    """What went wrong, named by what a caller does about it.

    ``retryable`` is ``True`` for a kind that the same request may get past later.
    Every other kind needs a change: a new credential, a fixed configuration, or a fixed program.
    """

    retryable: bool

    def __new__(cls, value: str, retryable: bool) -> FailureKind:
        """Create a member that carries whether its failures may pass on retry."""
        member = str.__new__(cls, value)
        member._value_ = value
        member.retryable = retryable
        return member

    # This library's caller passed a configuration or an argument that cannot work.
    CONFIGURATION = ("configuration", False)

    # This library refused what the other side sent: a token, a document, or a response that does not validate.
    REFUSED = ("refused", False)

    # The other side refused the request as sent, with a client error status or an OAuth error code.
    REJECTED = ("rejected", False)

    # The other side answered with a server error or a rate limit.
    SERVER_ERROR = ("server_error", True)

    # The request ran out of time.
    TIMEOUT = ("timeout", True)

    # An error this library does not classify, such as a fault in a caller-supplied handler.
    UNEXPECTED = ("unexpected", False)

    # The other side could not be reached: a name lookup, a connection or a transport failure.
    UNREACHABLE = ("unreachable", True)


class OAuthError(Exception):
    """Base exception for all apron-auth errors.

    ``kind`` says what went wrong and ``retryable`` whether the same request may succeed later.
    A subclass that fails in one way only declares ``default_kind``, and a raise may leave ``kind`` out.
    A subclass that fails in several ways declares none, and every raise must pass ``kind``.
    """

    default_kind: FailureKind | None = None

    def __init__(self, *args: object, kind: FailureKind | None = None) -> None:
        super().__init__(*args)
        if kind is None:
            kind = type(self).default_kind
        if not isinstance(kind, FailureKind):
            msg = f"{type(self).__name__} needs a kind from FailureKind"
            raise TypeError(msg)
        self.kind = kind

    @property
    def retryable(self) -> bool:
        """Whether the same request may succeed later without any change."""
        return self.kind.retryable


class ConfigurationError(OAuthError):
    """Provider configuration is invalid or incomplete, or an argument cannot work."""

    default_kind = FailureKind.CONFIGURATION


class IdentityFetchError(OAuthError):
    """Fetching user identity from the provider failed.

    ``kind`` tells an outage, which may pass, from a refusal, which cannot.
    """


# IdentityNotSupportedError follows its base class instead of A-Z order, because Python needs the base defined first.
class IdentityNotSupportedError(ConfigurationError):
    """No identity handler exists for this provider configuration."""


# IdentityScopeNotGrantedError follows IdentityFetchError for the same reason.
class IdentityScopeNotGrantedError(IdentityFetchError):
    """The token is known to lack a scope the provider's identity endpoint requires.

    Retrying with the same token cannot succeed.
    The caller must obtain a token that carries the required scope.
    """

    default_kind = FailureKind.REJECTED


class IssuerValidationError(OAuthError):
    """Authorization-response issuer (RFC 9207) did not match the expected issuer.

    Raised when a code exchange is refused because the authorization response's
    ``iss`` parameter is absent where required or names a different authorization
    server than the one the flow was configured for, the signature of an
    authorization-server mix-up.
    """

    default_kind = FailureKind.REFUSED


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


class RevocationError(OAuthError):
    """Token revocation failed at the provider."""


class StateError(OAuthError):
    """The OAuth state from a callback is missing, invalid, expired, already consumed, or not the pending state's."""

    default_kind = FailureKind.REFUSED


class TokenEndpointError(OAuthError):
    """A token-endpoint request failed. Base of the exchange and refresh errors, never raised itself.

    ``error_code`` holds the OAuth error code (RFC 6749) when the endpoint sent one, and is the empty string otherwise.
    """

    def __init__(self, *args: object, kind: FailureKind | None = None, error_code: str = "") -> None:
        super().__init__(*args, kind=kind)
        self.error_code = error_code


# The token-endpoint and token-validation errors follow their base classes instead of A-Z order, as above.
class TokenExchangeError(TokenEndpointError):
    """Authorization code exchange failed: the token endpoint refused the code, or this client refused its response."""


class IdTokenValidationError(TokenExchangeError):
    """The ID token of a code exchange is not shown to be issued to this client for the request it answers.

    The token may be unreadable, name another audience or authorized party, have expired, or name another issuer.
    """

    default_kind = FailureKind.REFUSED


class NonceValidationError(IdTokenValidationError):
    """A code exchange is not shown to answer the authorization request whose nonce it should carry.

    The response may carry no ID token, or one with no nonce or a different one.
    The pending state of an OpenID request may also have lost its nonce, so there is nothing to compare.
    The token response may answer an authorization request this client did not start.
    """


class TokenRefreshError(TokenEndpointError):
    """Token refresh failed.

    ``retryable`` tells an outage or a rate limit from a dead grant or a client fault.
    Read ``error_code`` to tell a dead grant (``invalid_grant``) from a client or configuration problem.
    """


class TokenValidationReason(StrEnum):
    """Why a signed token was refused, for a caller that counts or branches on refusals without reading text."""

    # The token names an audience other than the one the recipient answers to.
    AUDIENCE = "audience"
    # A claim is missing, has the wrong type, or does not validate.
    CLAIMS = "claims"
    # The token verified but its expiry has passed.
    EXPIRED = "expired"
    # The token is not a signed token, or its header or claims cannot be read.
    MALFORMED = "malformed"
    # No published key verifies the signature.
    SIGNATURE = "signature"
    # The token names an issuer the recipient does not trust.
    UNKNOWN_ISSUER = "unknown_issuer"
    # The token names a key the issuer does not publish.
    UNKNOWN_KEY = "unknown_key"
    # The token uses an algorithm or a header parameter this library does not accept.
    UNSUPPORTED = "unsupported"


class TokenValidationError(IdentityFetchError):
    """A signed token was refused: it is malformed, no published key verifies it, or its claims do not validate.

    Retrying the same token cannot succeed, so ``kind`` is always ``REFUSED``, and ``reason`` says why.
    A failure to fetch the issuer's signing keys is not a refusal, and raises the base class instead.
    """

    default_kind = FailureKind.REFUSED

    def __init__(self, *args: object, reason: TokenValidationReason) -> None:
        super().__init__(*args)
        if not isinstance(reason, TokenValidationReason):
            msg = f"{type(self).__name__} needs a reason from TokenValidationReason"
            raise TypeError(msg)
        self.reason = reason


class TokenExpiredError(TokenValidationError):
    """A signed token verified but has expired, so the caller must obtain a fresh one."""

    def __init__(self, *args: object) -> None:
        super().__init__(*args, reason=TokenValidationReason.EXPIRED)
