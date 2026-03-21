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
    """Token data returned from code exchange or refresh."""

    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    expires_in: int | None = None
    expires_at: float | None = None
    scope: str | None = None
    metadata: dict[str, Any] = {}


class OAuthPendingState(BaseModel, frozen=True):
    """State stored during the OAuth authorization flow."""

    state: str
    redirect_uri: str
    code_verifier: str | None = None
    created_at: float
