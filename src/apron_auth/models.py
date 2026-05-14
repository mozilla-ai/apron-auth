"""Data models for OAuth configuration, tokens, and state."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, SecretStr

AccessType = Literal["read", "write", "admin"]


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
    """OAuth provider configuration — endpoints, credentials, behaviour.

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
    """

    client_id: str
    client_secret: SecretStr
    authorize_url: str
    token_url: str
    revocation_url: str | None = None
    redirect_uri: str | None = None
    scopes: list[str] = []
    scope_separator: str = " "
    use_pkce: bool = True
    token_endpoint_auth_method: str = "client_secret_post"
    extra_params: dict[str, str] = {}
    disconnect_fully_revokes: bool = False
    scope_metadata: list[ScopeMetadata] = []
    required_scope_families: list[list[str]] = []
    can_assert_domain_ownership: bool = False


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
            returns a numeric identifier so the contract is stable.
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
            Callers gating domain-bound tenant grants should use
            :meth:`IdentityProfile.domain_owning_tenancy` rather than
            inspecting this flag directly. Defaults to ``False``.
    """

    id: str | None = None
    name: str | None = None
    domain: str | None = None
    raw: dict[str, Any] = {}
    owns_email_domain: bool = False


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
        """Return ``email`` iff the provider asserts it as verified, else ``None``.

        NOTE: a verified email proves the user controlled the inbox at
        the time of verification. It does NOT prove ongoing control or
        current employment. Callers must not use this as proof of
        domain affiliation — see :meth:`domain_owning_tenancy` for that
        question.
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
        """
        if self.provider and self.subject:
            return (self.provider, self.subject)
        return None


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
