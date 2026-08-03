"""Data models for OAuth configuration, tokens, and state."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, SecretStr, model_validator

from apron_auth.errors import IssuerValidationError
from apron_auth.scopes import resolve_implicit_scopes as _resolve_implicit_scopes

AccessType = Literal["read", "write", "admin"]


class TokenEndpointAuthMethod:
    """RFC 7591/8414 token_endpoint_auth_method values."""

    CLIENT_SECRET_POST = "client_secret_post"  # pragma: allowlist secret
    CLIENT_SECRET_BASIC = "client_secret_basic"  # pragma: allowlist secret
    NONE = "none"


class ApplicationType:
    """RFC 7591/OpenID Connect application_type values."""

    WEB = "web"
    NATIVE = "native"


class ScopeMetadata(BaseModel, frozen=True):
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


class ProviderConfig(BaseModel, frozen=True):
    """OAuth provider configuration — endpoints, credentials, behavior.

    Attributes:
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
            Google Workspace via the ``hd`` claim). Set by the preset
            at construction time. Consumers building domain-gated
            tenancy can refuse to wire up an incapable provider at
            startup rather than discovering the gap at login time.
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
            parameter (RFC 9207) before a code is redeemed. ``None`` when no
            issuer is known, which disables issuer validation entirely —
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
    token_endpoint_auth_method: str = TokenEndpointAuthMethod.CLIENT_SECRET_POST
    extra_params: dict[str, str] = {}
    disconnect_fully_revokes: bool = False
    scope_metadata: list[ScopeMetadata] = []
    required_scope_families: list[list[str]] = []
    can_assert_domain_ownership: bool = False
    implicit_scopes: dict[str, frozenset[str]] = {}
    issuer: str | None = None
    require_iss: bool = False
    resource: str | None = None

    @model_validator(mode="after")
    def _client_secret_presence_matches_auth_method(self) -> ProviderConfig:
        """Reject a config whose secret presence contradicts its auth method.

        The ``token_endpoint_auth_method`` decides the client type, and the
        secret must agree. A public client declares ``"none"`` and carries no
        secret; presenting one would attach client credentials to requests a
        public client must send unauthenticated. Any other method is a
        confidential client, for which the secret is mandatory.

        Returns:
            The validated config, unchanged.

        Raises:
            ValueError: If a public client carries a secret, or a
                confidential client lacks one.
        """
        is_public = self.token_endpoint_auth_method == TokenEndpointAuthMethod.NONE
        if is_public and self.client_secret is not None:
            msg = f"client_secret must be omitted when token_endpoint_auth_method is '{TokenEndpointAuthMethod.NONE}'"
            raise ValueError(msg)
        if not is_public and self.client_secret is None:
            msg = f"client_secret is required unless token_endpoint_auth_method is '{TokenEndpointAuthMethod.NONE}'"
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
        if not urlparse(self.resource).scheme:
            msg = "resource must be an absolute URI when set"
            raise ValueError(msg)
        return self

    def basic_auth(self) -> tuple[str, str] | None:
        """Return the client's HTTP Basic credential, or None for a public client.

        A public client declares a ``token_endpoint_auth_method`` of ``"none"``,
        presents no client authentication, and returns None. A confidential
        client authenticates with its ``client_id`` and ``client_secret``. The
        declared method drives the decision, so a public client presents no
        credential even if a secret lingers on the config.

        Returns:
            The ``(client_id, client_secret)`` pair for a confidential
            client, or ``None`` for a public client.
        """
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


class ServerMetadata(BaseModel, frozen=True):
    """OAuth endpoints and capabilities of an MCP server's authorization server.

    Mirrors the RFC 8414 authorization-server metadata fields relevant to an
    authorization-code flow, plus the registration endpoint from RFC 7591.
    Holds no client identity — only the server-advertised facts.

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
            when the metadata omits it. Used to validate the
            authorization-response ``iss`` parameter (RFC 9207).
        iss_parameter_supported: Whether the server advertises support for
            returning the ``iss`` parameter on the authorization response;
            ``False`` when the metadata omits the flag.
        supports_cimd: Whether the authorization server advertises support
            for Client ID Metadata Documents (CIMD) via
            ``client_id_metadata_document_supported``; ``False`` when the
            metadata omits the flag.
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


class ClientRegistration(BaseModel, frozen=True):
    """Client credentials issued by RFC 7591 dynamic client registration.

    The issued ``client_id`` and ``client_secret`` are bound to the
    authorization server that minted them and are not valid at any other
    authorization server.

    NOTE: a caller that persists these credentials must store them keyed by
    the minting issuer (the ``issuer`` of the ``ServerMetadata`` whose
    ``registration_url`` produced them) and must not present them to a
    different authorization server; this library is stateless and holds no
    credentials, so it cannot enforce the binding on the caller's behalf.

    Attributes:
        client_id: The client identifier issued by the registration
            endpoint.
        client_secret: The issued client secret for a confidential client;
            ``None`` for a public client.
        token_endpoint_auth_method: The token-endpoint authentication method
            the server registered for this client. It is authoritative for
            this client and may differ from the server's advertised set, and
            is ``None`` when the registration response states no method.
    """

    client_id: str
    client_secret: SecretStr | None = None
    token_endpoint_auth_method: str | None = None


class TokenSet(BaseModel, frozen=True):
    """Token data returned from code exchange or refresh.

    Attributes:
        access_token: The access token issued by the provider.
        token_type: Token type, typically ``"Bearer"``.
        refresh_token: Optional refresh token for obtaining new access tokens.
        expires_in: Token lifetime in seconds as reported by the provider.
        expires_at: Absolute expiry time as a Unix timestamp.
        scope: Space-separated scopes granted by the provider.
        metadata: Additional fields from the provider's token endpoint
            response that are not captured by the named attributes above
            (e.g. Slack's ``team_id``).  Populated automatically.
        context: Caller-supplied context carried opaquely from
            ``OAuthPendingState.metadata`` through the authorization flow.
            Populated when ``exchange_code`` auto-consumes from a
            ``StateStore``; empty otherwise.
    """

    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    expires_in: int | None = None
    expires_at: float | None = None
    scope: str | None = None
    metadata: dict[str, Any] = {}
    context: dict[str, Any] = {}


class IdentityMaterial(BaseModel, frozen=True):
    """The material an identity handler establishes a user's identity from.

    Constructed from a :class:`TokenSet` immediately before dispatching
    to a provider's identity handler, this type is the single boundary
    that decides what token material crosses into handler code. It
    deliberately exposes only the fields identity resolution needs — the
    bearer access token and, for OpenID Connect (OIDC) providers, the ID
    token — and omits the refresh token and caller-supplied context
    carried on :class:`TokenSet`. Identity handlers can be consumer- or
    third-party-supplied, so withholding the refresh token and opaque
    caller context from them is defense in depth: the omitted fields are
    structurally absent, not merely blanked.

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
    """

    access_token: str
    id_token: str | None = None

    @classmethod
    def from_token_set(cls, tokens: TokenSet) -> IdentityMaterial:
        """Narrow a :class:`TokenSet` to the material identity handlers may use.

        The ID token is read from the token-endpoint response, where
        providers return it as the ``id_token`` field that lands on
        :attr:`TokenSet.metadata`. The refresh token and caller context
        on the ``TokenSet`` are intentionally not carried over.

        Args:
            tokens: The token set to narrow.

        Returns:
            The identity material: the access token and, when the
            response carried one, the OIDC ID token.
        """
        id_token = tokens.metadata.get("id_token")
        return cls(
            access_token=tokens.access_token,
            id_token=id_token if isinstance(id_token, str) else None,
        )


class TenancyContext(BaseModel, frozen=True):
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


class IdentityProfile(BaseModel, frozen=True):
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
        provider: Name of the OAuth provider that issued this profile
            (e.g. ``"google"``, ``"github"``). Populated by each
            provider's ``fetch_identity`` implementation. Used by
            :meth:`identity_key` to produce a ``(provider, subject)``
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

    provider: str | None = None
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

        Returns ``None`` if either field is missing or empty. Consumers
        should key their user/identity tables on this tuple rather than
        on ``email`` to avoid cross-provider account hijack via email
        collision.

        Returns:
            The ``(provider, subject)`` pair, or ``None`` when either
            field is missing or empty.
        """
        if self.provider and self.subject:
            return (self.provider, self.subject)
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


class OAuthPendingState(BaseModel, frozen=True):
    """State stored during the OAuth authorization flow.

    Attributes:
        state: Unique token identifying this authorization request.
        redirect_uri: Redirect URI for this flow.
        code_verifier: PKCE code verifier, if PKCE is enabled.
        created_at: Unix timestamp when this state was created.
        metadata: Opaque caller-supplied context that apron-auth carries
            but never interprets.  Attach application-specific data
            (e.g. ``user_id``, ``tenant_id``) here; it will be preserved
            through ``StateStore`` save/consume and surfaced on
            ``TokenSet.context`` when ``exchange_code`` auto-consumes.
    """

    state: str
    redirect_uri: str
    code_verifier: str | None = None
    created_at: float
    metadata: dict[str, Any] = {}
