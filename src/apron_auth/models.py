"""Data models for OAuth configuration, tokens, and state."""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, StrEnum, auto, unique
from typing import Any, Literal, NoReturn, Self, TypeVar, assert_never
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    Field,
    ModelWrapValidatorHandler,
    SecretStr,
    ValidationError,
    ValidationInfo,
    model_validator,
)

from apron_auth._clock import DEFAULT_MAX_AGE_SECONDS
from apron_auth._urls import (
    AuthorityCredential,
    authority_credential,
    matches_suffix,
    query_parameters,
    uses_allowed_transport,
)
from apron_auth.errors import ConfigurationError, IssuerValidationError
from apron_auth.scopes import resolve_implicit_scopes as _resolve_implicit_scopes

logger = logging.getLogger(__name__)

AccessType = Literal["read", "write", "admin"]

_ModelT = TypeVar("_ModelT", bound=BaseModel)

# The facts a config takes from the provider it names, rather than repeating them.
FACTS_TAKEN_FROM_PROVIDER = ("can_assert_domain_ownership", "disconnect_fully_revokes", "scope_separator")

# The authorization request parameters that bind the request to the client, plus the request object parameters
# that would replace them all. extra_params must not set them.
RESERVED_AUTHORIZATION_PARAMS = frozenset(
    {
        "client_id",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "redirect_uri",
        "request",
        "request_uri",
        "resource",
        "response_type",
        "state",
    }
)

# The part a validation refusal puts in a field's path for a mapping key, which names no field of ours.
_DICT_KEY_MARKER = "[key]"

# The field that records which URL fields a model was built accepting plain HTTP for.
_PLAIN_HTTP_WAIVER = "allow_insecure_http_for"

# The token that states a plain-HTTP waiver was built in code. It is compared by identity, so a
# waiver arriving as data cannot state it.
_WAIVER_SENTINEL = object()


@unique
class UrlTransport(Enum):
    """Each member is one rule for what a URL field's scheme has to state about its transport."""

    # The field names an endpoint a request is sent to, and what travels there needs TLS.
    TLS_REQUIRED = auto()
    # The field identifies something rather than naming an endpoint, so its scheme states no transport.
    UNCHECKED = auto()


@unique
class UrlField(StrEnum):
    """Every URL field of this library's models, named by the field it stands for.

    None may carry a credential in its authority.
    A member's transport is required of it on a model that declares endpoints, and nowhere else.
    A provider's profile image is no member, because this library only ever reads it back out.

    Attributes:
        transport: What this field's scheme has to state about its transport.
    """

    _transport: UrlTransport

    def __new__(cls, value: str, transport: UrlTransport) -> UrlField:
        """Create a member from its field name and what that field's scheme has to state."""
        member = str.__new__(cls, value)
        member._value_ = value
        member._transport = transport
        return member

    @property
    def transport(self) -> UrlTransport:
        """What this field's scheme has to state about its transport."""
        return self._transport

    AUTHORIZE_URL = ("authorize_url", UrlTransport.TLS_REQUIRED)
    ISSUER = ("issuer", UrlTransport.TLS_REQUIRED)
    JWKS_URL = ("jwks_url", UrlTransport.TLS_REQUIRED)
    REDIRECT_URI = ("redirect_uri", UrlTransport.TLS_REQUIRED)
    REGISTRATION_URL = ("registration_url", UrlTransport.TLS_REQUIRED)
    RESOURCE = ("resource", UrlTransport.UNCHECKED)
    REVOCATION_URL = ("revocation_url", UrlTransport.TLS_REQUIRED)
    TOKEN_URL = ("token_url", UrlTransport.TLS_REQUIRED)
    USERINFO_URL = ("userinfo_url", UrlTransport.TLS_REQUIRED)


@unique
class TokenEndpointAuthMethod(StrEnum):
    """Each member is one token-endpoint authentication method this library can perform.

    A member's value is the method's registered name (RFC 7591/8414), which is what goes on the wire, and a
    member is declared as ``(value, requires_secret)``.

    Attributes:
        requires_secret: Whether a client authenticating with this method sends a client secret.
            A client that does not is a public client, which presents no client authentication.
    """

    _requires_secret: bool

    def __new__(cls, value: str, requires_secret: bool) -> TokenEndpointAuthMethod:
        """Create a member that carries whether its client sends a secret."""
        member = str.__new__(cls, value)
        member._value_ = value
        member._requires_secret = requires_secret
        return member

    @property
    def requires_secret(self) -> bool:
        """Whether a client authenticating with this method sends a client secret."""
        return self._requires_secret

    CLIENT_SECRET_BASIC = ("client_secret_basic", True)  # pragma: allowlist secret
    CLIENT_SECRET_POST = ("client_secret_post", True)  # pragma: allowlist secret
    NONE = ("none", False)


@unique
class ApplicationType(StrEnum):
    """Each member is one client application type a registration request can declare.

    A member's value is the type's registered name (RFC 7591/OpenID Connect Dynamic Client Registration 1.0).
    """

    NATIVE = "native"
    WEB = "web"


@dataclass(frozen=True, kw_only=True)
class ProviderFacts:
    """The facts that differ between the providers this library knows by name.

    Attributes:
        can_assert_domain_ownership: Whether the provider's tokens can carry a tenancy that asserts the
            authenticated user belongs to the email's domain, such as Google Workspace's ``hd`` claim.
            :attr:`ProviderConfig.can_assert_domain_ownership` describes what a consumer does with it.
        disconnect_fully_revokes: Whether revoking a token removes the user's portal-level OAuth grant.
            :attr:`ProviderConfig.disconnect_fully_revokes` describes the consequences.
        display_name: The provider's name as it appears in messages and documentation.
        host_suffixes: The provider's own OAuth endpoint hosts, matched on a label boundary.
            They decide whether a config that names the provider may use its identity handler, so
            they decide where an access token may be sent.
            NOTE: A config that names the provider may have endpoints outside them, such as a
            Salesforce org on a custom login domain.
        identity_handler_class_name: The name of the class in the provider's module that fetches identity.
            The class takes no constructor arguments.
            A member names it rather than holding it, because every provider module imports this one.
        revocation_handler_class_name: The name of the class in the provider's module that revokes a
            token, named rather than held for the same reason. The class takes no constructor arguments.
            ``None`` where the provider needs no revocation of its own, which leaves a config that
            declares a revocation endpoint to the standard RFC 7009 revocation.
        scope_separator: The string the provider's scope parameter is joined with.
            NOTE: It must not be empty, as :attr:`ProviderConfig.scope_separator` requires.
        user_token_response_field: The member of a token-endpoint response that carries the token the
            provider issued for the authorizing person, beside the application's own.
            ``None`` where the provider issues one token per response.
    """

    can_assert_domain_ownership: bool
    disconnect_fully_revokes: bool
    display_name: str
    host_suffixes: tuple[str, ...]
    identity_handler_class_name: str
    revocation_handler_class_name: str | None
    scope_separator: str
    user_token_response_field: str | None


@unique
class Provider(StrEnum):
    """The OAuth providers this library knows by name, each with the facts that differ between them.

    A member's value is its module name under ``apron_auth.providers``, and a member is declared as
    ``(value, facts)``. Each fact is read through the property of its own name, and nothing supported
    changes a member's facts, because they decide where an access token may be sent.
    """

    _facts: ProviderFacts

    def __new__(cls, value: str, facts: ProviderFacts) -> Provider:
        """Create a member from its module name and the facts that differ between providers."""
        member = str.__new__(cls, value)
        member._value_ = value
        member._facts = facts
        return member

    @property
    def can_assert_domain_ownership(self) -> bool:
        """Whether the provider's tokens can carry a tenancy that asserts ownership of an email's domain."""
        return self._facts.can_assert_domain_ownership

    @property
    def disconnect_fully_revokes(self) -> bool:
        """Whether revoking a token removes the user's portal-level OAuth grant."""
        return self._facts.disconnect_fully_revokes

    @property
    def display_name(self) -> str:
        """The provider's name as it appears in messages and documentation."""
        return self._facts.display_name

    @property
    def host_suffixes(self) -> tuple[str, ...]:
        """The provider's own OAuth endpoint hosts, matched on a label boundary."""
        return self._facts.host_suffixes

    @property
    def identity_handler_class_name(self) -> str:
        """The name of the class in the provider's module that fetches identity."""
        return self._facts.identity_handler_class_name

    @property
    def revocation_handler_class_name(self) -> str | None:
        """The name of the class in the provider's module that revokes a token."""
        return self._facts.revocation_handler_class_name

    @property
    def scope_separator(self) -> str:
        """The string the provider's scope parameter is joined with."""
        return self._facts.scope_separator

    @property
    def user_token_response_field(self) -> str | None:
        """The member of a token-endpoint response carrying the token issued for the authorizing person."""
        return self._facts.user_token_response_field

    ATLASSIAN = (
        "atlassian",
        ProviderFacts(
            can_assert_domain_ownership=False,
            disconnect_fully_revokes=False,
            display_name="Atlassian",
            host_suffixes=("auth.atlassian.com",),
            identity_handler_class_name="AtlassianIdentityHandler",
            revocation_handler_class_name=None,
            scope_separator=" ",
            user_token_response_field=None,
        ),
    )
    GITHUB = (
        "github",
        ProviderFacts(
            can_assert_domain_ownership=False,
            disconnect_fully_revokes=True,
            display_name="GitHub",
            host_suffixes=("github.com",),
            identity_handler_class_name="GitHubIdentityHandler",
            revocation_handler_class_name="GitHubRevocationHandler",
            scope_separator=" ",
            user_token_response_field=None,
        ),
    )
    GOOGLE = (
        "google",
        ProviderFacts(
            can_assert_domain_ownership=True,
            disconnect_fully_revokes=True,
            display_name="Google",
            host_suffixes=("google.com", "googleapis.com"),
            identity_handler_class_name="GoogleIdentityHandler",
            revocation_handler_class_name="GoogleRevocationHandler",
            scope_separator=" ",
            user_token_response_field=None,
        ),
    )
    HUBSPOT = (
        "hubspot",
        ProviderFacts(
            can_assert_domain_ownership=False,
            disconnect_fully_revokes=False,
            display_name="HubSpot",
            host_suffixes=("api.hubapi.com", "app.hubspot.com"),
            identity_handler_class_name="HubSpotIdentityHandler",
            revocation_handler_class_name="HubSpotRevocationHandler",
            scope_separator=" ",
            user_token_response_field=None,
        ),
    )
    LINEAR = (
        "linear",
        ProviderFacts(
            can_assert_domain_ownership=False,
            disconnect_fully_revokes=False,
            display_name="Linear",
            host_suffixes=("linear.app",),
            identity_handler_class_name="LinearIdentityHandler",
            revocation_handler_class_name=None,
            scope_separator=",",
            user_token_response_field=None,
        ),
    )
    MICROSOFT = (
        "microsoft",
        ProviderFacts(
            can_assert_domain_ownership=True,
            disconnect_fully_revokes=False,
            display_name="Microsoft",
            host_suffixes=("login.microsoftonline.com",),
            identity_handler_class_name="MicrosoftIdentityHandler",
            revocation_handler_class_name=None,
            scope_separator=" ",
            user_token_response_field=None,
        ),
    )
    NOTION = (
        "notion",
        ProviderFacts(
            can_assert_domain_ownership=False,
            disconnect_fully_revokes=False,
            display_name="Notion",
            host_suffixes=("api.notion.com",),
            identity_handler_class_name="NotionIdentityHandler",
            revocation_handler_class_name="NotionRevocationHandler",
            scope_separator=" ",
            user_token_response_field=None,
        ),
    )
    SALESFORCE = (
        "salesforce",
        ProviderFacts(
            can_assert_domain_ownership=False,
            disconnect_fully_revokes=False,
            display_name="Salesforce",
            host_suffixes=("salesforce.com",),
            identity_handler_class_name="SalesforceIdentityHandler",
            revocation_handler_class_name=None,
            scope_separator=" ",
            user_token_response_field=None,
        ),
    )
    SLACK = (
        "slack",
        ProviderFacts(
            can_assert_domain_ownership=False,
            disconnect_fully_revokes=False,
            display_name="Slack",
            host_suffixes=("slack.com",),
            identity_handler_class_name="SlackIdentityHandler",
            revocation_handler_class_name="SlackRevocationHandler",
            scope_separator=",",
            user_token_response_field="authed_user",
        ),
    )
    TYPEFORM = (
        "typeform",
        ProviderFacts(
            can_assert_domain_ownership=False,
            disconnect_fully_revokes=False,
            display_name="Typeform",
            host_suffixes=("api.typeform.com",),
            identity_handler_class_name="TypeformIdentityHandler",
            revocation_handler_class_name=None,
            scope_separator=" ",
            user_token_response_field=None,
        ),
    )


def _build_allowing_plain_http(
    cls: type[_ModelT], fields: tuple[UrlField | str, ...], values: dict[str, Any]
) -> _ModelT:
    """Build a model that accepts plain HTTP for the named URL fields, and say so in the log.

    NOTE: Nothing is logged for a build that is refused, so a line in the log names a waiver in force.

    Args:
        cls: The model to build.
        fields: The URL fields plain HTTP is accepted for.
        values: The field values to build from.

    Returns:
        The built model, recording the fields it accepts plain HTTP for.

    Raises:
        ConfigurationError: If the values are refused, or a name is no URL field.
    """
    waiver = frozenset(fields)
    model = cls.model_validate({**values, _PLAIN_HTTP_WAIVER: waiver}, context={_PLAIN_HTTP_WAIVER: _WAIVER_SENTINEL})
    logger.warning("plain http accepted for %s; use this for local development only", sorted(str(f) for f in waiver))
    return model


def _refusal_text(error: ValidationError) -> str:
    """Return a model's refusals as one line, dropping the value the framework attached to each.

    NOTE: A refusal a model's own validator wrote is passed through as it stands, so a validator
    that interpolates a value into its message still carries that value here.

    Args:
        error: The refusal raised while validating the model.

    Returns:
        One line naming each refused field and why, or the model-level reason when a refusal names no field.
    """
    refusals: list[str] = []
    for entry in error.errors(include_url=False, include_input=False, include_context=False):
        reason = entry["msg"].removeprefix("Value error, ")
        # NOTE: A mapping key of the marker's own text in the marker's own position is dropped with it.
        path = entry["loc"]
        if path and path[-1] == _DICT_KEY_MARKER:
            path = path[:-1]
        field = ".".join(str(part) for part in path)
        refusals.append(f"{field}: {reason}" if field else reason)
    return "; ".join(refusals)


def _refuse_a_url_carrying_a_credential(model: BaseModel) -> BaseModel:
    """Refuse a URL field whose authority carries a credential, naming the field that carries it.

    A field of :class:`UrlField` that the model does not hold is skipped, so one rule covers models
    holding different subsets of them.

    Args:
        model: The model to read the URL fields of.

    Returns:
        The model, unchanged.

    Raises:
        ValueError: If a URL field carries userinfo, or its authority cannot be read.
    """
    for field in UrlField:
        url = getattr(model, field.value, None)
        if url is None:
            continue
        credential = authority_credential(url)
        match credential:
            case AuthorityCredential.ABSENT:
                continue
            case AuthorityCredential.MALFORMED:
                msg = f"{field} is malformed"
                raise ValueError(msg)
            case AuthorityCredential.PRESENT:
                msg = f"{field} must not carry userinfo"
                raise ValueError(msg)
            case _:
                assert_never(credential)
    return model


def _refuse_a_url_without_tls(model: BaseModel) -> BaseModel:
    """Refuse a URL field stating a transport this model does not accept.

    A field naming an endpoint must state ``https``, the only scheme that protects what a request
    carries.
    A loopback host is accepted over ``http`` with no waiver, because a request to it reaches no
    network.
    Every other scheme is refused, including one this library cannot send, and so is an empty value.
    A field of :class:`UrlField` that the model does not hold is skipped, so one rule covers models
    holding different subsets of them.

    Args:
        model: The model to read the URL fields of.

    Returns:
        The model, unchanged.

    Raises:
        ValueError: If a URL field states a transport this model does not accept, or is empty, or a
            recorded waiver names a field that needs none.
    """
    waived: frozenset[UrlField] = getattr(model, _PLAIN_HTTP_WAIVER, frozenset())
    for field in sorted(waived):
        if field.value not in type(model).model_fields or field.transport is UrlTransport.UNCHECKED:
            msg = f"{field} needs no waiver"
            raise ValueError(msg)
    for field in UrlField:
        url = getattr(model, field.value, None)
        if url is None or field.transport is UrlTransport.UNCHECKED:
            continue
        if not url:
            msg = f"{field} must not be empty"
            raise ValueError(msg)
        if uses_allowed_transport(url, plain_http_allowed=field in waived):
            continue
        msg = f"{field} must use https, or http on a loopback host"
        raise ValueError(msg)
    return model


def _refuse_a_waiver_that_did_not_come_from_code(model: BaseModel, info: ValidationInfo) -> BaseModel:
    """Refuse a plain-HTTP waiver that was not stated in code.

    A waiver read back out of storage would carry one machine's exception to wherever the data was
    moved.

    NOTE: The waiver is read off the built model, because an input validated from attributes states
    no mapping to read.

    Args:
        model: The model to read the waiver of.
        info: The validation this runs within.

    Returns:
        The model, unchanged.

    Raises:
        ValueError: If the model records a waiver that was not stated in code.
    """
    waived = getattr(model, _PLAIN_HTTP_WAIVER, frozenset())
    context = info.context if isinstance(info.context, Mapping) else {}
    if waived and context.get(_PLAIN_HTTP_WAIVER) is not _WAIVER_SENTINEL:
        msg = f"{_PLAIN_HTTP_WAIVER} is stated through unsafe.allow_plain_http, not as data"
        raise ValueError(msg)
    return model


def _refuse_without_repeating_the_value(
    cls: type[BaseModel], data: Any, handler: ModelWrapValidatorHandler[Any]
) -> Any:
    """Validate a model, refusing with a configuration error that repeats no value it was given.

    A validation refusal carries the raw value it was given, which for a model that holds a
    credential means a caller recording the refusal records the credential with it.

    NOTE: Attach this as a model's last validator, so it wraps the others. One attached to a base
    class does not wrap a subclass's own validators, whose refusals would then escape unscrubbed.

    NOTE: A model validated as a field of another model refuses with this error rather than one the
    outer model can collect. The refusal names the field inside this model and not the path to it.
    Any other refusal the outer model would have reported is lost.

    Args:
        cls: The model being validated.
        data: The value to validate, as it arrived.
        handler: The validation this wraps.

    Returns:
        The validated model.

    Raises:
        ConfigurationError: If validation refuses the value.
    """
    refusals: str | None = None
    try:
        return handler(data)
    except ValidationError as error:
        refusals = _refusal_text(error)
    # NOTE: This raise stays outside the except block, so the refusal it replaces is not reachable from it.
    raise ConfigurationError(refusals)


# Attach this as a model's last validator, so it wraps the others. It is shared rather than written in
# each model, so it types against the base and not each concrete model.
_REPEATS_NO_VALUE = model_validator(mode="wrap")(
    classmethod(_refuse_without_repeating_the_value)  # ty: ignore[invalid-argument-type]
)

# Attach this to every model that holds a URL field, so one rule decides what any of them may carry.
_URLS_CARRY_NO_USERINFO = model_validator(mode="after")(_refuse_a_url_carrying_a_credential)

# Attach this to every model that declares endpoints, so one rule decides what their schemes must state.
_URLS_STATE_THEIR_TRANSPORT = model_validator(mode="after")(_refuse_a_url_without_tls)

# Attach this to every model that records a plain-HTTP waiver, so only code can state one.
_WAIVER_COMES_FROM_CODE = model_validator(mode="after")(_refuse_a_waiver_that_did_not_come_from_code)


class _RefusesWithoutRepeating(BaseModel):
    """A model that refuses without repeating the value it was given, at each entry point of its own.

    A framework refusal carries the raw value it was given, which for a model that holds a credential
    means a caller recording the refusal records the credential with it. Each entry point here raises a
    configuration error stating what it refused, naming the field where the refusal names one.

    NOTE: A model must also attach the shared wrap validator as its last member, which covers the entry
    points the framework owns. A wrap validator attached here would not wrap a subclass's own validators.
    """

    def __reduce__(self) -> Any:
        """Reduce for pickling, refusing a model that records a plain-HTTP waiver.

        A waiver states one machine's exception, and pickling carries it to wherever the bytes go.

        Returns:
            What the framework reduces this model to.

        Raises:
            ConfigurationError: If the model records a waiver.
        """
        if getattr(self, _PLAIN_HTTP_WAIVER, frozenset()):
            msg = f"a model that accepts plain http cannot be stored; state {_PLAIN_HTTP_WAIVER} in code instead"
            raise ConfigurationError(msg)
        return super().__reduce__()

    def __setattr__(self, name: str, value: Any) -> None:
        """Set an attribute, refusing without repeating the value it was given.

        NOTE: Only a validation refusal is scrubbed. A model that is not frozen can refuse a change with
        another error class, which passes through as the framework wrote it.

        Args:
            name: The name of the attribute to set.
            value: The value to set it to.

        Raises:
            ConfigurationError: If the change is refused.
        """
        refusals: str | None = None
        try:
            super().__setattr__(name, value)
        except ValidationError as error:
            refusals = _refusal_text(error)
        else:
            return
        # NOTE: This raise stays outside the except block, so the refusal it replaces is not reachable from it.
        raise ConfigurationError(refusals)

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        """Validate a JSON document, refusing without repeating the value it was given.

        A document the parser refuses is refused before any field of it is read, so the framework's
        refusal carries the whole document rather than one field's value.

        Args:
            json_data: The document to validate.
            **kwargs: The validation options, passed on as given.

        Returns:
            The validated model.

        Raises:
            ConfigurationError: If validation refuses the document.
        """
        refusals: str | None = None
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as error:
            refusals = _refusal_text(error)
        # NOTE: This raise stays outside the except block, so the refusal it replaces is not reachable from it.
        raise ConfigurationError(refusals)

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        """Validate a mapping of strings, refusing without repeating the value it was given.

        A value that is not a mapping is refused before any field of it is read, so the framework's
        refusal carries the whole value rather than one field's.

        Args:
            obj: The value to validate.
            **kwargs: The validation options, passed on as given.

        Returns:
            The validated model.

        Raises:
            ConfigurationError: If validation refuses the value.
        """
        refusals: str | None = None
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError as error:
            refusals = _refusal_text(error)
        # NOTE: This raise stays outside the except block, so the refusal it replaces is not reachable from it.
        raise ConfigurationError(refusals)


class ScopeMetadata(_RefusesWithoutRepeating, frozen=True):
    """Consent-UI metadata for a single OAuth scope.

    Field shape mirrors apron-tools' ``ScopeMetadata`` so a consumer can
    concatenate ``CapabilityGroup.metadata()`` from apron-tools with
    :attr:`ProviderConfig.scope_metadata` to produce a complete
    ``list[ScopeMetadata]`` for a consent picker. apron-auth declares
    metadata only for the cross-cutting scopes its presets inject;
    apron-tools owns metadata for tool-level scopes.

    Attributes:
        scope: The OAuth scope string sent to the provider, exactly as it
            appears in :attr:`ProviderConfig.scopes`.
        label: Short human-readable name for the consent picker.
        description: Longer explanation of what granting this scope does;
            should match the provider's authorize-page wording where
            possible so the consent picker stays in sync with what the
            user sees at the provider.
        access_type: Coarse classification used for visual grouping in
            the consent picker.
        required: When ``True``, the consumer's UI should not allow the
            user to deselect the scope — typically because the OAuth
            flow itself depends on it (e.g. ``openid`` for identity,
            ``offline_access`` for refresh tokens).
    """

    scope: str
    label: str
    description: str
    access_type: AccessType
    required: bool = False

    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE


class ProviderConfig(_RefusesWithoutRepeating, frozen=True, extra="forbid"):
    """OAuth provider configuration — endpoints, credentials, behavior.

    Construction and validation refuse a field this model does not define, so a renamed or mistyped
    one cannot be dropped silently and leave the config weaker than the caller asked for.

    No URL field carries userinfo, because each one is sent to the provider, handed to a browser,
    or recorded wherever the config is.

    Attributes:
        scope_separator: The delimiter the ``scope`` request parameter is joined with,
            and the one a granted scope string is split on.
            An empty value is refused at construction.
            Defaults to a single space (RFC 6749 section 3.3).
        extra_params: Fixed parameters added to every authorization request.
            A reserved parameter is refused at construction, and the error names it.
            Reserved parameters bind the request to the client, such as ``state`` and ``code_challenge``,
            or replace the request as a whole, such as ``request_uri``.
        disconnect_fully_revokes: Whether ``revoke_token`` removes the
            user's portal-level OAuth grant.

            When ``True``, calling
            :meth:`~apron_auth.client.OAuthClient.revoke_token` is
            sufficient to force a fresh consent screen on the next
            authorization flow — enabling automatic scope-reduction
            (tier 1) end-to-end inside the OAuth flow.

            When ``False``, revocation only invalidates the current
            token. A subsequent authorization flow reuses the existing
            portal-level grant and the user keeps their previously-
            granted scopes regardless of what's requested. Consumers
            must surface a deep link to the provider's app-management
            settings (tier 3) for the user to remove the grant
            manually.

            Defaults to ``False``. Over-claiming silently breaks scope
            reduction; under-claiming harmlessly falls back to the
            manual deep-link path.
        scope_metadata: Consent-UI metadata for the cross-cutting scopes
            the preset injects into :attr:`scopes` (e.g. ``openid``,
            ``offline_access``). Empty when the preset does not inject
            any scopes of its own. Consumers building a consent picker
            should concatenate apron-tools' ``CapabilityGroup.metadata()``
            with this list to cover both tool-level and cross-cutting
            scopes without a parallel hand-maintained table.
        required_scope_families: Set-level scope constraints expressing
            "at least one of these scope sets must be requested".  Each
            inner list is an "at-least-one-of" group; the constraint is
            satisfied when the final scope selection contains at least
            one scope drawn from at least one family.  Used by providers
            (e.g. Slack) whose token endpoint applies a set-level OR
            rule that cannot be expressed as per-scope
            :attr:`ScopeMetadata.required`.  A consent picker can
            enforce the constraint generically without provider-specific
            knowledge.  Defaults to empty (no set-level constraint).
        can_assert_domain_ownership: ``True`` only for providers whose
            tokens can in principle carry a tenancy that asserts the
            authenticated user belongs to the email's domain (e.g.
            Google Workspace via the ``hd`` claim). Taken from
            :attr:`provider` when the config names one, and set by the
            preset otherwise. Consumers building domain-gated tenancy
            can refuse to wire up an incapable provider at startup
            rather than discovering the gap at login time.
            Defaults to ``False``.
        implicit_scopes: Mapping from a high-level scope to the
            finer-grained scopes it implicitly includes — used to avoid
            false "missing scope" reports. Holding a high-level scope
            often implies holding narrower ones: a token with GitHub's
            ``repo`` implicitly holds ``public_repo``, so checking that
            token for ``public_repo`` alone would wrongly report it as
            missing. :meth:`resolve_implicit_scopes` expands a granted set
            against this mapping. Set by the preset; empty when a provider
            has no such relationships.
        issuer: Expected issuer identifier (RFC 8414) of the authorization
            server, used to validate the authorization-response ``iss``
            parameter (RFC 9207) before a code is redeemed, and the ``iss``
            claim of an ID token the code exchange returns. Both are compared
            exactly, so a templated or scheme-less value does not belong here.
            ``None`` when no issuer is known, which disables both checks —
            the default for presets that do not opt in.
        require_iss: Whether an authorization response that omits ``iss``
            must be rejected. Set ``True`` when the authorization server
            advertises support for the ``iss`` parameter, so a stripped
            ``iss`` cannot silently bypass the mix-up check. Ignored when
            :attr:`issuer` is ``None``. Defaults to ``False``.

            The default leaves a hand-built config that sets :attr:`issuer`
            but not this flag catching only a *mismatched* ``iss``, not a
            *stripped* one — an attacker who removes ``iss`` slips past. A
            caller that knows its authorization server emits ``iss`` should
            set this ``True`` to close that gap; :func:`apron_auth.mcp.to_provider_config`
            does so automatically from the discovered metadata.
        resource: RFC 8707 resource indicator identifying the service the
            issued token is audience-bound to. When set, it must be an
            absolute URI without a fragment (RFC 8707); an invalid value is
            rejected at construction. It is sent on the authorization request
            and on the token-exchange and refresh requests, so the
            authorization server can restrict the token's audience to this
            resource. ``None`` (the default) emits no ``resource`` parameter
            anywhere, preserving behavior for providers that do not use
            resource indicators.
        use_builtin_identity_handler: Whether this library may establish identity with the identity
            handler of the provider :attr:`provider` names.
            Set ``False`` to leave a handler passed to :class:`~apron_auth.client.OAuthClient` as the
            only source of identity. A config that names no provider has no handler of its own either
            way. Defaults to ``True``.
        max_pending_age_seconds: The age, in seconds, past which a pending authorization request is refused
            at the code exchange. A pending state exactly this old still passes that check.
            Must be a positive finite number. Defaults to 600 (ten minutes).
        provider: The built-in provider this config is labeled with, which every preset sets to its own.
            ``None`` for a hand-built config, and for a generic OpenID or MCP config.
            When set, each fact :data:`FACTS_TAKEN_FROM_PROVIDER` names must equal the member's, and a
            config that contradicts one is refused at construction.
            NOTE: The label is not an attestation. Construction checks nothing else about a config
            against the member, so a caller must not read this as proof of where the endpoints lead.
            NOTE: Only construction takes and checks a member's facts. A config whose provider is set
            through :meth:`~pydantic.BaseModel.model_copy` keeps the facts it already carried.
        allow_insecure_http_for: The URL fields this config accepts plain HTTP for. Empty by
            default, and stated only through :meth:`unsafe.allow_plain_http`, so a waiver read back
            out of storage is refused. A loopback host needs no waiver, because a request to one
            reaches no network.
            NOTE: A copy made through ``model_copy``, ``copy.replace``, ``copy.copy`` or
            ``copy.deepcopy`` runs no validator, so one can carry any waiver and any URL.
            NOTE: A config recording a waiver cannot be validated as a field of another model,
            because that validation cannot tell a waiver stated in code from one read out of data.
    """

    client_id: str
    client_secret: SecretStr | None = None
    authorize_url: str
    token_url: str
    revocation_url: str | None = None
    redirect_uri: str | None = None
    scopes: list[str] = []
    scope_separator: str = " "
    use_pkce: bool = True
    token_endpoint_auth_method: TokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_POST
    extra_params: dict[str, str] = {}
    disconnect_fully_revokes: bool = False
    scope_metadata: list[ScopeMetadata] = []
    required_scope_families: list[list[str]] = []
    can_assert_domain_ownership: bool = False
    implicit_scopes: dict[str, frozenset[str]] = {}
    issuer: str | None = None
    require_iss: bool = False
    resource: str | None = None
    use_builtin_identity_handler: bool = True
    max_pending_age_seconds: float = DEFAULT_MAX_AGE_SECONDS
    provider: Provider | None = None
    allow_insecure_http_for: frozenset[UrlField] = Field(default=frozenset(), json_schema_extra={"readOnly": True})

    # The name is lowercase because it reads as a namespace at the call site, not as a type.
    class unsafe:  # noqa: N801
        """Builders that give up a protection this config otherwise requires."""

        @staticmethod
        def allow_plain_http(*fields: UrlField | str, **values: Any) -> ProviderConfig:
            """Build a configuration that accepts plain HTTP for the named URL fields.

            Every other URL field still has to state TLS, so a waiver reaches no field it does not name.
            A loopback host needs no waiver, because a request to it reaches no network.
            A waiver states what this configuration accepts, not what its values happen to be, so one
            naming a field that holds ``https`` is accepted and recorded.

            NOTE: This builds a :class:`ProviderConfig`, including when it is reached through a subclass.

            Args:
                *fields: The URL fields plain HTTP is accepted for.
                **values: The field values to build from.

            Returns:
                The built configuration, recording the fields it accepts plain HTTP for.

            Raises:
                ConfigurationError: If the values are refused, or a name is no URL field.
            """
            return _build_allowing_plain_http(ProviderConfig, fields, values)

    @model_validator(mode="after")
    def _client_secret_presence_matches_auth_method(self) -> ProviderConfig:
        """Reject a config whose secret presence contradicts its auth method.

        The ``token_endpoint_auth_method`` decides the client type, and the secret must agree.
        A method that requires no secret is a public client, and presenting one would attach client
        credentials to requests a public client must send unauthenticated.
        Every other method requires the secret it sends.

        Returns:
            The validated config, unchanged.

        Raises:
            ValueError: If a public client carries a secret, or a
                confidential client lacks one.
        """
        is_public = not self.token_endpoint_auth_method.requires_secret
        if is_public and self.client_secret is not None:
            msg = f"client_secret must be omitted when token_endpoint_auth_method is '{TokenEndpointAuthMethod.NONE}'"
            raise ValueError(msg)
        if not is_public and self.client_secret is None:
            msg = f"client_secret is required unless token_endpoint_auth_method is '{TokenEndpointAuthMethod.NONE}'"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _authorize_url_does_not_set_reserved_parameters(self) -> ProviderConfig:
        """Reject an authorization URL whose own query sets a parameter reserved for the request itself.

        A reserved parameter binds the request to the client, or replaces the request as a whole.
        The request drops such a parameter rather than sending it, so a configuration that sets one
        never sends what it states, and refusing it at construction reports that before any sign-in.

        Returns:
            The validated config, unchanged.

        Raises:
            ValueError: If the ``authorize_url`` query holds a reserved authorization request parameter.
        """
        refused = sorted(RESERVED_AUTHORIZATION_PARAMS & query_parameters(self.authorize_url).keys())
        if refused:
            msg = f"authorize_url must not set reserved authorization request parameters: {', '.join(refused)}"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _extra_params_do_not_set_reserved_parameters(self) -> ProviderConfig:
        """Reject an extra parameter that is reserved for the authorization request itself.

        A reserved parameter binds the request to the client, or replaces the request as a whole.
        Refusing it at construction reports the misconfiguration before any sign-in.

        Returns:
            The validated config, unchanged.

        Raises:
            ValueError: If ``extra_params`` holds a reserved authorization request parameter.
        """
        refused = sorted(RESERVED_AUTHORIZATION_PARAMS & self.extra_params.keys())
        if refused:
            msg = f"extra_params must not set reserved authorization request parameters: {', '.join(refused)}"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _max_pending_age_is_positive_and_finite(self) -> ProviderConfig:
        """Reject a maximum pending age that would refuse every pending state or none.

        Returns:
            The validated config, unchanged.

        Raises:
            ValueError: If ``max_pending_age_seconds`` is zero, negative, infinite, or not a number.
        """
        if not math.isfinite(self.max_pending_age_seconds) or self.max_pending_age_seconds <= 0:
            msg = "max_pending_age_seconds must be a positive finite number"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _resource_is_absolute_uri(self) -> ProviderConfig:
        """Reject a resource indicator that is not an absolute URI without a fragment.

        RFC 8707 requires a resource indicator to be an absolute URI (RFC 3986
        section 4.3): it carries a scheme and no fragment.
        ``None`` is allowed and disables the indicator. Validating at
        construction keeps an empty, relative, or fragment-bearing value from
        reaching the authorization server, where it would silently weaken or
        break audience binding.

        Returns:
            The validated config, unchanged.

        Raises:
            ValueError: If ``resource`` is set but is not an absolute URI, or
                carries a fragment.
        """
        if self.resource is None:
            return self
        if "#" in self.resource:
            msg = "resource must not contain a fragment"
            raise ValueError(msg)
        try:
            scheme = urlparse(self.resource).scheme
        except ValueError as exc:
            msg = "resource is malformed"
            raise ValueError(msg) from exc
        if not scheme:
            msg = "resource must be an absolute URI when set"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _scope_separator_is_not_empty(self) -> ProviderConfig:
        """Reject a separator that no scope string can be split on.

        Returns:
            The validated config, unchanged.

        Raises:
            ValueError: If ``scope_separator`` is empty.
        """
        if not self.scope_separator:
            msg = "scope_separator must not be empty"
            raise ValueError(msg)
        return self

    @model_validator(mode="before")
    @classmethod
    def _take_provider_facts_from_member(cls, data: Any) -> Any:
        """Fill the facts a provider member states, for a config that names one and leaves them out.

        The member is the one statement of a provider's facts, so a config that names it need not
        repeat them. A value given explicitly is left alone, and the check after this one refuses
        one that contradicts the member.

        Args:
            data: The raw input, which is a mapping when the config is built from keywords or JSON.

        Returns:
            A mapping with each stated fact filled in where it was left out, leaving the caller's own
            mapping as it was.
        """
        if not isinstance(data, Mapping):
            return data
        try:
            member = Provider(data["provider"])
        except (KeyError, ValueError):
            return data
        data = dict(data)
        for fact in FACTS_TAKEN_FROM_PROVIDER:
            data.setdefault(fact, getattr(member, fact))
        return data

    @model_validator(mode="after")
    def _provider_facts_match_member(self) -> ProviderConfig:
        """Reject a config whose per-provider facts contradict its provider.

        The member states a provider's facts once. A config that named a member and carried a different
        value for one of them would answer one way from the config and another from the member.

        Returns:
            The validated config, unchanged.

        Raises:
            ValueError: If ``provider`` is set and a fact the config takes from it differs from the
                member's.
        """
        if self.provider is None:
            return self
        for fact in FACTS_TAKEN_FROM_PROVIDER:
            stated = getattr(self.provider, fact)
            carried = getattr(self, fact)
            if carried != stated:
                msg = f"{fact} must be {stated!r} for provider {self.provider.display_name}, got {carried!r}"
                raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _revocation_endpoint_sits_with_the_token_endpoint(self) -> ProviderConfig:
        """Reject a config that revokes a token somewhere other than where it was issued.

        A revocation request carries a bearer token to ``revocation_url``. A token is revoked at the
        host that issued it, or at another of the named provider's own hosts, so any other host
        would be sent a token it never issued. A subdomain of the issuing host is another host.
        NOTE: A copy made with ``model_copy`` runs no validator and can carry any endpoint.

        Returns:
            The validated config, unchanged.

        Raises:
            ValueError: If ``provider`` is set and the revocation and token endpoints name
                neither one host nor two of the named provider's. The message names the hosts
                alone, because a rejected authority can carry a credential.
        """
        if self.provider is None or self.revocation_url is None:
            return self
        token_host = urlparse(self.token_url).hostname or ""
        revocation_host = urlparse(self.revocation_url).hostname or ""
        # A subdomain is a separate authority, so only the host itself answers for the token it issued.
        if revocation_host and revocation_host == token_host:
            return self
        suffixes = self.provider.host_suffixes
        if matches_suffix(revocation_host, suffixes) and matches_suffix(token_host, suffixes):
            return self
        display_name = self.provider.display_name
        msg = (
            f"revocation_url names {revocation_host} and token_url names {token_host}. A token is "
            f"revoked where it was issued, so both must name one host, or both must name "
            f"{display_name} hosts."
        )
        raise ValueError(msg)

    def basic_auth(self) -> tuple[str, str] | None:
        """Return the client's HTTP Basic credential, or None for a public client.

        A public client declares a ``token_endpoint_auth_method`` of ``"none"``, presents no client
        authentication, and returns None.
        A confidential client authenticates with its ``client_id`` and ``client_secret``.
        The declared method drives the decision, so a public client presents no credential even if a secret
        lingers on the config.

        Returns:
            The ``(client_id, client_secret)`` pair for a confidential
            client, or ``None`` for a public client.
        """
        # NOTE: This compares the value rather than reading the member's facts, because a config built
        # without validation holds whatever was passed, which may be a plain string.
        if self.token_endpoint_auth_method == TokenEndpointAuthMethod.NONE:
            return None
        if self.client_secret is None:
            return None
        return (self.client_id, self.client_secret.get_secret_value())

    def validate_issuer(self, received_iss: str | None) -> None:
        """Validate an authorization-response ``iss`` (RFC 9207) against :attr:`issuer`.

        Guards against an authorization-server mix-up: a code minted by one
        authorization server must not be redeemed at another. Validation applies
        only when :attr:`issuer` is set; without a known issuer there is nothing
        to compare against and this is a no-op. A present ``iss`` must match the
        expected issuer exactly; an absent one is rejected only when
        :attr:`require_iss` is set, so a stripped parameter cannot bypass the
        check against a server known to send it.

        Args:
            received_iss: The ``iss`` parameter from the authorization response,
                or ``None`` when the response carried none.

        Raises:
            IssuerValidationError: If ``received_iss`` is present and does not
                match :attr:`issuer`, or is absent while :attr:`require_iss` is
                set.
        """
        if self.issuer is None:
            return
        if received_iss is None:
            if self.require_iss:
                msg = "authorization response is missing the required iss parameter"
                raise IssuerValidationError(msg)
            return
        if received_iss != self.issuer:
            msg = "authorization response iss does not match the expected issuer"
            raise IssuerValidationError(msg)

    def resolve_implicit_scopes(self, granted: set[str]) -> set[str]:
        """Return ``granted`` expanded with every scope it transitively implies.

        Implications come from this provider's :attr:`implicit_scopes`, so a
        token holding a high-level scope also holds the finer-grained scopes
        nested under it. The input set is not mutated.

        Args:
            granted: The scopes a token was granted.

        Returns:
            A new set: ``granted`` plus every scope it transitively implies.
        """
        return _resolve_implicit_scopes(granted, self.implicit_scopes)

    _urls_carry_no_userinfo = _URLS_CARRY_NO_USERINFO
    _waiver_comes_from_code = _WAIVER_COMES_FROM_CODE
    _urls_state_their_transport = _URLS_STATE_THEIR_TRANSPORT
    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE


class ServerMetadata(_RefusesWithoutRepeating, frozen=True, extra="forbid"):
    """OAuth metadata discovered for an authorization server.

    Construction and validation refuse a field this model does not define, so a renamed or mistyped
    one cannot be dropped silently and leave an issuer check weaker than the document stated.

    Mirrors the RFC 8414 authorization-server metadata fields relevant to an
    authorization-code flow, plus the registration endpoint from RFC 7591 and
    the RFC 9728 protected-resource identifier. Holds no client identity — only
    the server-advertised facts.

    A field the server does not advertise is left at its default.

    Attributes:
        authorize_url: The authorization endpoint URL.
        token_url: The token endpoint URL.
        registration_url: The dynamic client registration endpoint, or
            ``None`` when the server advertises none.
        revocation_url: The token revocation endpoint, or ``None`` when the
            server advertises none.
        scopes_supported: The scopes the server advertises support for;
            empty when it advertises none.
        code_challenge_methods: The PKCE code-challenge methods the server
            advertises; empty when it advertises none.
        token_endpoint_auth_methods: The token-endpoint authentication
            methods the server advertises; empty when it advertises none.
        issuer: The authorization server's issuer identifier, or ``None``
            when the metadata was built by hand rather than discovered. Used to validate the
            authorization-response ``iss`` parameter (RFC 9207).
        iss_parameter_supported: Whether the server advertises support for
            returning the ``iss`` parameter on the authorization response;
            ``False`` when the metadata omits the flag.
        supports_cimd: Whether the authorization server advertises support
            for Client ID Metadata Documents (CIMD) via
            ``client_id_metadata_document_supported``; ``False`` when the
            metadata omits the flag.
        resource: The protected resource's RFC 8707 resource identifier, taken
            from the RFC 9728 protected-resource metadata ``resource`` field;
            ``None`` when the metadata omits it or its value is not a string.
            This is the canonical URI to which a token's audience is bound.
        userinfo_url: The OpenID Connect userinfo endpoint, or ``None`` when the metadata omits it.
            An OpenID provider need not advertise one.
        jwks_url: The issuer's JSON Web Key Set (JWKS) URL, or ``None`` when the metadata omits it.
        allow_insecure_http_for: The URL fields this metadata accepts plain HTTP for. Empty by
            default, and stated only through :meth:`unsafe.allow_plain_http`, so a waiver read back
            out of storage is refused. A loopback host needs no waiver, because a request to one
            reaches no network.
            NOTE: A copy made through ``model_copy``, ``copy.replace``, ``copy.copy`` or
            ``copy.deepcopy`` runs no validator, so one can carry any waiver and any URL.
            NOTE: A metadata recording a waiver cannot be validated as a field of another model,
            because that validation cannot tell a waiver stated in code from one read out of data.
    """

    authorize_url: str
    token_url: str
    registration_url: str | None = None
    revocation_url: str | None = None
    scopes_supported: list[str] = []
    code_challenge_methods: list[str] = []
    token_endpoint_auth_methods: list[str] = []
    issuer: str | None = None
    iss_parameter_supported: bool = False
    supports_cimd: bool = False
    resource: str | None = None
    userinfo_url: str | None = None
    jwks_url: str | None = None
    allow_insecure_http_for: frozenset[UrlField] = Field(default=frozenset(), json_schema_extra={"readOnly": True})

    # The name is lowercase because it reads as a namespace at the call site, not as a type.
    class unsafe:  # noqa: N801
        """Builders that give up a protection this metadata otherwise requires."""

        @staticmethod
        def allow_plain_http(*fields: UrlField | str, **values: Any) -> ServerMetadata:
            """Build a metadata that accepts plain HTTP for the named URL fields.

            Every other URL field still has to state TLS, so a waiver reaches no field it does not name.
            A loopback host needs no waiver, because a request to it reaches no network.
            A waiver states what this metadata accepts, not what its values happen to be, so one naming
            a field that holds ``https`` is accepted and recorded.

            NOTE: This builds a :class:`ServerMetadata`, including when it is reached through a subclass.

            Args:
                *fields: The URL fields plain HTTP is accepted for.
                **values: The field values to build from.

            Returns:
                The built metadata, recording the fields it accepts plain HTTP for.

            Raises:
                ConfigurationError: If the values are refused, or a name is no URL field.
            """
            return _build_allowing_plain_http(ServerMetadata, fields, values)

    _urls_carry_no_userinfo = _URLS_CARRY_NO_USERINFO
    _waiver_comes_from_code = _WAIVER_COMES_FROM_CODE
    _urls_state_their_transport = _URLS_STATE_THEIR_TRANSPORT
    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE


class ClientRegistration(_RefusesWithoutRepeating, frozen=True, extra="forbid"):
    """A client's credentials at one authorization server.

    RFC 7591 dynamic client registration issues them, and a caller that registered out of band or hosts a
    Client ID Metadata Document (CIMD) states its own.

    Construction and validation refuse a field this model does not define, so a renamed or mistyped
    one cannot be dropped silently and load a confidential client as a public one.

    NOTE: Credentials an authorization server issued are not valid at any other authorization server.
    A caller that persists them must store them keyed by the minting issuer (the ``issuer`` of the
    ``ServerMetadata`` whose ``registration_url`` produced them) and must not present them to a different
    authorization server. This library is stateless and holds no credentials, so it cannot enforce the
    binding on the caller's behalf.

    Attributes:
        client_id: The client identifier, issued by a registration endpoint, registered out of band, or a
            CIMD client identifier URL.
        client_secret: The client secret for a confidential client; ``None`` for a public client.
        token_endpoint_auth_method: The token-endpoint authentication method the server registered for this
            client. It is authoritative for this client and may differ from the server's advertised set,
            and is ``None`` when no method was registered.
    """

    client_id: str
    client_secret: SecretStr | None = None
    token_endpoint_auth_method: TokenEndpointAuthMethod | None = None

    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE


class UserToken(_RefusesWithoutRepeating, frozen=True, extra="forbid"):
    """The token a provider issues for the person who authorized an application, beside the application's own.

    A provider that grants an application its own token and the authorizing person a second one
    returns the person's token in a member of its own, as Slack does in ``authed_user``.
    This model is that token, so a caller can read, refresh and revoke it by name.

    Construction and validation refuse a field this model does not define, so a renamed or mistyped
    one cannot be dropped silently and lose what the provider sent.

    NOTE: A nested member stating no access token carries no user token, so the token set states
    none and keeps the member in its extras.

    Attributes:
        access_token: The access token issued for the person.
        token_type: Token type, as the provider states it.
        refresh_token: The refresh token for this token, where the provider rotates it.
        expires_in: Token lifetime in seconds as reported by the provider.
        expires_at: Absolute expiry time as a Unix timestamp.
        scope: Scopes granted for this token, delimited by the provider's scope separator.
        user_id: The provider's identifier for the person the token acts as.
        extras: Fields of the provider's nested member that the named attributes above do not
            capture, including one whose value is not of the type its own field states.
            Populated automatically.
            NOTE: An attribute above states what this library read, and takes precedence over a
            field of the same name here, which states only what the provider sent.
    """

    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    expires_in: int | None = None
    expires_at: float | None = None
    scope: str | None = None
    user_id: str | None = None
    extras: dict[str, Any] = {}

    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE


class TokenSet(_RefusesWithoutRepeating, frozen=True, extra="forbid"):
    """Token data returned from code exchange or refresh.

    Construction and validation refuse a field this model does not define, so a renamed or mistyped
    one cannot be dropped silently and lose what the provider or the caller attached.

    Attributes:
        access_token: The access token issued by the provider.
        token_type: Token type, typically ``"Bearer"``.
        refresh_token: Optional refresh token for obtaining new access tokens.
        expires_in: Token lifetime in seconds as reported by the provider.
        expires_at: Absolute expiry time as a Unix timestamp.
        scope: Scopes granted by the provider, delimited by the
            provider's scope separator.
        user_token: The token the provider issued for the authorizing person, where it issues one
            beside the application's own. Populated automatically.
        extras: Fields of the provider's token-endpoint response that the named attributes above do not
            capture, such as Slack's ``team_id``, including one whose value is not of the type its own
            field states. Populated automatically.
            NOTE: An attribute above states what this library read, and takes precedence over a
            field of the same name here, which states only what the provider sent.
            NOTE: A field carried here can hold credential material, such as a refresh token a
            provider sent as a list, so it is as sensitive as the named attributes above.
        context: Caller-supplied context carried opaquely from ``OAuthPendingState.context``.
            It is empty for a token set that does not come from a code exchange.
    """

    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    expires_in: int | None = None
    expires_at: float | None = None
    scope: str | None = None
    user_token: UserToken | None = None
    extras: dict[str, Any] = {}
    context: dict[str, Any] = {}

    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE


class FreshTokenSet(TokenSet):
    """A token set that a code exchange or a refresh returned in this process.

    It is the only token set identity can be established from.
    An identity handler may accept the ID token in it without a signature check,
    which is safe only for a token the token endpoint returned over TLS.
    Deserializing one is refused, through this model's own entry points and as a field of another model,
    so a persisted token set reloads as a plain :class:`TokenSet`, and a refresh produces a fresh one again.
    Pickling one is refused, because freshness does not survive being stored.

    NOTE: Keyword construction is how this library issues one.
    A caller who builds, copies or validates one directly must establish that freshness itself.
    """

    def __reduce__(self) -> NoReturn:
        """Refuse to pickle a fresh token set.

        Raises:
            ConfigurationError: Always.
        """
        msg = "A fresh token set cannot be stored. Persist its fields, and refresh when identity is needed again."
        raise ConfigurationError(msg)

    @model_validator(mode="before")
    @classmethod
    def _refuse_reload_as_a_field(cls, data: Any, info: ValidationInfo) -> Any:
        # NOTE: Pydantic sets field_name only when another model validates this one as a field.
        # That is how a persisted model reloads it. Keyword construction has no field name.
        if info.field_name is not None:
            raise cls._stored_data_refusal()
        return data

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> NoReturn:
        """Refuse to build a fresh token set from stored data.

        Raises:
            ConfigurationError: Always.
        """
        raise cls._stored_data_refusal()

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> NoReturn:
        """Refuse to build a fresh token set from stored JSON.

        Raises:
            ConfigurationError: Always.
        """
        raise cls._stored_data_refusal()

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> NoReturn:
        """Refuse to build a fresh token set from stored strings.

        Raises:
            ConfigurationError: Always.
        """
        raise cls._stored_data_refusal()

    @staticmethod
    def _stored_data_refusal() -> ConfigurationError:
        msg = "A fresh token set cannot be built from stored data. Only a code exchange or a refresh produces one."
        return ConfigurationError(msg)

    # NOTE: The name differs from the base's. Re-using that name keeps the base's place in the chain,
    # which is ahead of any after or wrap rule of this model's own, whose refusals would then escape.
    _repeats_no_value_last = _REPEATS_NO_VALUE


class IdentityMaterial(_RefusesWithoutRepeating, frozen=True):
    """The material an identity handler establishes a user's identity from.

    Constructed from a :class:`FreshTokenSet` immediately before dispatching
    to a provider's identity handler, this type is the single boundary
    that decides what token material crosses into handler code. It
    deliberately exposes only the fields identity resolution needs — the
    bearer access token, the granted scopes, and, for OpenID Connect
    (OIDC) providers, the ID token — and omits the refresh token and
    caller-supplied context carried on :class:`TokenSet`. Identity
    handlers can be consumer- or third-party-supplied, so withholding the
    refresh token and opaque caller context from them is defense in
    depth: the omitted fields are structurally absent, not merely blanked.

    NOTE: a provider-specific token-endpoint extra that a future handler
    needs (e.g. an instance URL) should be added here as a named field
    and populated in :meth:`from_token_set`, rather than widening the
    handler interface to the full :class:`TokenSet`.

    Attributes:
        access_token: The bearer access token used to call the
            provider's identity or directory APIs.
        id_token: The OIDC ID token from the token-endpoint response
            when present, else ``None``. Carries the issuer-asserted
            identity and tenancy claims a handler can validate as a
            trust boundary. ``None`` for non-OIDC providers or when the
            ``openid`` scope was not granted.
        scope: The granted scopes, delimited by the provider's scope
            separator. ``None`` when no scope information is available.
            A handler must treat ``None`` or a blank value as an unknown
            grant and must not infer one.
    """

    access_token: str
    id_token: str | None = None
    scope: str | None = None

    @classmethod
    def from_token_set(cls, tokens: FreshTokenSet) -> IdentityMaterial:
        """Narrow a :class:`FreshTokenSet` to the material identity handlers may use.

        The refresh token and caller context are intentionally not carried over.

        Args:
            tokens: The fresh token set to narrow.

        Returns:
            The identity material: the access token, the granted scopes,
            and, when the response carried one, the OIDC ID token.
        """
        id_token = tokens.extras.get("id_token")
        return cls(
            access_token=tokens.access_token,
            id_token=id_token if isinstance(id_token, str) else None,
            scope=tokens.scope,
        )

    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE


class TenancyContext(_RefusesWithoutRepeating, frozen=True):
    """Scoping container an OAuth access token operates within.

    The generic name covers SaaS vernacular variants — workspace,
    organization, team, instance, portal, site, tenant — without
    privileging one term. Three normalized fields cover the common
    cross-provider consumer needs (account binding, display, deep-
    linking); provider-specific extras fall through to :attr:`raw`.

    Each normalized field may independently be ``None`` when the
    provider's response does not expose that fact. Callers must not
    assume any of ``id`` / ``name`` / ``domain`` are populated.

    Attributes:
        id: Tenant identifier as exposed by the provider (e.g. Slack
            ``team_id``, Linear organization id, Atlassian ``cloudId``,
            HubSpot ``hub_id``). Cast to ``str`` where the provider
            returns a numeric identifier so the contract is stable. It
            is a provider-assigned identifier for binding and display —
            not itself an authorization grant. Consumers gating
            domain or tenant access must do so on
            :attr:`owns_email_domain` (via
            :meth:`IdentityProfile.owns_domain`), never on the mere
            presence of an ``id``.
        name: Human-readable display name for the tenant (e.g. Slack
            ``team_name``, Linear organization name).
        domain: Domain or canonical URL for the tenant (e.g. Slack
            ``team_domain``, HubSpot ``hub_domain``, Atlassian site URL,
            Salesforce MyDomain host).
        raw: Provider-specific payload for this tenant (Slack-namespaced
            claims, Notion ``workspace_id``, Atlassian ``avatarUrl`` /
            ``scopes``, etc.). Used as the escape hatch for fields not
            covered by the three normalized slots above.
        owns_email_domain: ``True`` only when the provider asserts that
            this tenancy controls the email domain of the authenticated
            user (e.g. Google with the ``hd`` claim present). Set per
            identity at ``fetch_identity`` time by the provider handler.
            It must be set only from a verified, non-mutable assertion
            (a domain-authority claim or an admin-verified directory
            lookup) — never from a self-assertable claim such as a raw
            email address or UPN. A provider may set it on several
            tenancies at once when it asserts several domains for one
            tenant, so callers gating domain-bound tenant grants should
            use :meth:`IdentityProfile.owns_domain` rather than
            inspecting this flag directly. Defaults to ``False``.
    """

    id: str | None = None
    name: str | None = None
    domain: str | None = None
    raw: dict[str, Any] = {}
    owns_email_domain: bool = False

    def _verified_domain(self) -> str | None:
        """Return the domain this tenancy owns, normalized for comparison.

        ``None`` if the tenancy asserts no ownership, and if it asserts
        ownership without naming a domain — neither leaves anything to
        compare against.

        Returns:
            The normalized (trimmed, lowercased) owned domain, or ``None``
            when the tenancy owns no domain to compare against.
        """
        if not self.owns_email_domain or self.domain is None:
            return None
        return self.domain.strip().lower() or None

    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE


class IdentityProfile(_RefusesWithoutRepeating, frozen=True):
    """Normalized identity fields fetched from a provider.

    ``IdentityProfile`` answers "who authenticated?". The companion
    :attr:`tenancies` field answers "what scope of resources does this
    token operate within?" — the workspace, organization, tenant,
    instance, portal, or site the token is bound to. The two facts
    are kept distinct because most multi-tenant SaaS providers return
    both on the same userinfo response and conflating them forces
    handlers to make lossy "pick one" decisions for tokens that span
    multiple tenants (Atlassian's accessible-resources is the canonical
    example).

    Attributes:
        provider: The OAuth provider that issued this profile.
            A provider with a built-in preset is its :class:`Provider` member, and the member's value validates
            back into the member, so a profile rebuilt from a dump holds the member too.
            Any other provider is a string naming it, such as ``oidc:<issuer>``.
            Either form compares equal to its string value.
            Used by :meth:`identity_key` to produce a ``(provider, subject)``
            tuple suitable for keying a consumer's user table without
            cross-provider collision.
        subject: Provider user identifier when available.
        email: User email address when available.
        email_verified: Whether the provider reports the email as verified.
        name: Human-readable display name.
        username: Provider handle/login where available.
        avatar_url: Provider profile image URL when available.
        tenancies: Scoping containers the token operates within. Empty
            for providers with no tenancy concept (GitHub OAuth Apps,
            Typeform, personal Google). One entry for single-tenant
            providers. Multiple entries are possible for providers
            whose tokens span several tenants (Atlassian).
        raw: Full provider response payload(s) for advanced callers.
    """

    provider: Provider | str | None = Field(default=None, union_mode="left_to_right")
    subject: str | None = None
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    username: str | None = None
    avatar_url: str | None = None
    tenancies: tuple[TenancyContext, ...] = ()
    raw: dict[str, Any] = {}

    def verified_email(self) -> str | None:
        """Return ``email`` if the provider asserts it as verified, otherwise ``None``.

        NOTE: a verified email proves the user controlled the inbox at
        the time of verification. It does NOT prove ongoing control or
        current employment. Callers must not use this as proof of
        domain affiliation — see :meth:`owns_domain` for that question.

        Returns:
            The email when the provider reports it verified, else ``None``.
        """
        if self.email_verified and self.email:
            return self.email
        return None

    def identity_key(self) -> tuple[str, str] | None:
        """Return ``(provider, subject)``, the recommended primary key for users.

        Both parts are plain strings, whether :attr:`provider` holds a member or a string.
        Returns ``None`` if either field is missing or empty. Consumers
        should key their user/identity tables on this tuple rather than
        on ``email`` to avoid cross-provider account hijack via email
        collision.

        Returns:
            The ``(provider, subject)`` pair, or ``None`` when either
            field is missing or empty.
        """
        if self.provider and self.subject:
            return (str(self.provider), self.subject)
        return None

    def domain_owning_tenancies(self) -> tuple[TenancyContext, ...]:
        """Return every tenancy that verifiably owns the domain it names.

        A directory tenant asserting several admin-verified domains
        contributes one entry per domain, so this enumerates rather than
        reducing to a lossy "pick one". A tenancy flagged as domain-owning
        that names no domain offers nothing to gate on and does not
        qualify, so a truthiness check here agrees with
        :meth:`owns_domain`.

        Use :meth:`owns_domain` to gate on a specific domain; use this to
        enumerate or display the set. :attr:`tenancies` stays available
        for the unfiltered view.

        Returns:
            The qualifying tenancies, in provider order. That order is
            not generally guaranteed, so callers must not read
            significance into the first entry.
        """
        return tuple(tenancy for tenancy in self.tenancies if tenancy._verified_domain() is not None)

    def owns_domain(self, domain: str) -> bool:
        """Report whether any tenancy asserts the user belongs to ``domain``.

        This is the sanctioned gate for "does this identity verifiably
        belong to domain D?". Every tenancy is considered, so the answer
        holds for providers that assert several domains for one tenant.

        Matching is exact once surrounding whitespace is trimmed and case
        is folded. A parent domain does not confer ownership of its
        subdomains, nor a subdomain of its parent — each must be asserted
        in its own right.

        Args:
            domain: Domain to test ownership of. A blank value names no
                domain and so never matches, including against a tenancy
                whose own domain is blank.

        Returns:
            ``True`` when some tenancy asserts ownership of ``domain``.
        """
        target = domain.strip().lower()
        if not target:
            return False
        return any(tenancy._verified_domain() == target for tenancy in self.tenancies)

    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE


class OAuthPendingState(_RefusesWithoutRepeating, frozen=True, extra="forbid"):
    """State stored during the OAuth authorization flow.

    Construction and validation refuse a field this model does not define, so a renamed or mistyped
    one cannot be dropped silently and lose the context a caller attached.

    Attributes:
        state: Unique token identifying this authorization request.
        redirect_uri: Redirect URI for this flow.
        code_verifier: PKCE code verifier, if PKCE is enabled.
        nonce: OpenID Connect nonce sent with the request, if the request asks for the ``openid`` scope.
        created_at: Unix timestamp when this state was created.
        context: Opaque caller-supplied context that apron-auth carries but never interprets.
            Attach application-specific data such as ``user_id`` or ``tenant_id`` here.
    """

    state: str
    redirect_uri: str
    code_verifier: str | None = None
    nonce: str | None = None
    created_at: float
    context: dict[str, Any] = {}

    # No transport rule: the redirect URI is the one a config already stated, and a config that
    # accepts plain HTTP for it records no waiver here to read.
    _urls_carry_no_userinfo = _URLS_CARRY_NO_USERINFO
    # Attached last, so it wraps every validator above it.
    _repeats_no_value = _REPEATS_NO_VALUE
