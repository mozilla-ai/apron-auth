"""Data models for OAuth configuration, tokens, and state."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, SecretStr


class ProviderConfig(BaseModel, frozen=True):
    """OAuth provider configuration — endpoints, credentials, behaviour."""

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
