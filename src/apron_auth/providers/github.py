"""GitHub OAuth provider preset and revocation handler.

``disconnect_fully_revokes=True``: verified per GitHub's REST API
documentation for ``DELETE /applications/{client_id}/grant``. The
endpoint removes the user's entire OAuth authorization for the app
(204 on success), so a subsequent re-auth presents a fresh consent
screen and the next granted scope set is exactly what the
authorization request asks for.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError, RevocationError
from apron_auth.models import IdentityProfile, ProviderConfig, ScopeMetadata

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


logger = logging.getLogger(__name__)

_GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
_GITHUB_EMAILS_URL = "https://api.github.com/user/emails"
_GITHUB_IDENTITY_HOST_SUFFIXES = ("github.com",)
_GITHUB_USER_URL = "https://api.github.com/user"

BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="read:user",
        label="User Profile",
        description="Read access to your GitHub profile data",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="user:email",
        label="Email Address",
        description="Read access to your email addresses for account identification",
        access_type="read",
        required=True,
    ),
]

BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]


def _derive_github_email(user_payload: dict[str, Any], emails_payload: Any) -> tuple[str | None, bool | None]:
    if isinstance(emails_payload, list):
        for item in emails_payload:
            if not isinstance(item, dict):
                continue
            if item.get("primary") and item.get("verified") and item.get("email"):
                return str(item["email"]), True

        for item in emails_payload:
            if not isinstance(item, dict):
                continue
            if item.get("verified") and item.get("email"):
                return str(item["email"]), True

    email = user_payload.get("email")
    if email:
        return str(email), False
    return None, None


class GitHubIdentityHandler:
    """Fetch identity fields from GitHub profile and email APIs."""

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a GitHub access token."""
        del config
        headers = {
            "Authorization": f"Bearer {access_token}",
            **_GITHUB_API_HEADERS,
        }
        try:
            async with httpx.AsyncClient() as client:
                user_response = await client.get(_GITHUB_USER_URL, headers=headers)
                user_response.raise_for_status()
                emails_response = await client.get(_GITHUB_EMAILS_URL, headers=headers)
                emails_response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch GitHub identity: {exc}") from exc

        try:
            user_payload = user_response.json()
            emails_payload = emails_response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse GitHub identity response: {exc}") from exc

        email, email_verified = _derive_github_email(user_payload, emails_payload)
        subject = user_payload.get("id")

        return IdentityProfile(
            subject=str(subject) if subject is not None else None,
            email=email,
            email_verified=email_verified,
            name=user_payload.get("name") or user_payload.get("login"),
            username=user_payload.get("login"),
            avatar_url=user_payload.get("avatar_url"),
            raw={"user": user_payload, "emails": emails_payload},
        )


class GitHubRevocationHandler:
    """GitHub OAuth grant revocation via authenticated DELETE.

    Targets ``DELETE /applications/{client_id}/grant``, which removes
    the user's entire authorization for the OAuth app so that a
    subsequent re-auth presents a fresh consent screen — required for
    scope-reduction flows. The alternative ``/token`` endpoint only
    invalidates a single access token and re-auth silently reuses the
    existing grant.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke the GitHub OAuth grant at the configured revocation endpoint."""
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
        revocation_url = config.revocation_url
        if self._client is not None:
            return await self._send(self._client, token, revocation_url, config)
        async with httpx.AsyncClient() as client:
            return await self._send(client, token, revocation_url, config)

    async def _send(
        self,
        client: httpx.AsyncClient,
        token: str,
        revocation_url: str,
        config: ProviderConfig,
    ) -> bool:
        """Send the revocation request and return success status."""
        try:
            response = await client.request(
                "DELETE",
                revocation_url,
                auth=(config.client_id, config.client_secret.get_secret_value()),
                headers=_GITHUB_API_HEADERS,
                json={"access_token": token},
            )
        except httpx.RequestError as exc:
            raise RevocationError(str(exc)) from exc
        # 204: grant removed. 404: already gone — idempotent re-disconnect.
        if response.status_code in (204, 404):
            return True
        # 422: validation failed or spam-throttled per GitHub docs. Treat
        # as a soft failure so callers can continue with local cleanup.
        if response.status_code == 422:
            logger.warning(
                "GitHub grant revocation returned 422 (validation failed "
                "or spam-throttled); the grant may still exist at GitHub"
            )
            return False
        logger.warning(
            "GitHub grant revocation returned unexpected status %s",
            response.status_code,
        )
        return False


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the GitHub identity handler when config matches GitHub hosts."""
    hosts = (config.authorize_url, config.token_url)
    for url in hosts:
        host = urlparse(url).hostname or ""
        if any(host == suffix or host.endswith("." + suffix) for suffix in _GITHUB_IDENTITY_HOST_SUFFIXES):
            return GitHubIdentityHandler()
    return None


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a GitHub OAuth provider configuration.

    Scopes from BASE_SCOPES are merged automatically — ``read:user`` and
    ``user:email`` are required for account identification on the
    consent screen.
    """
    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        revocation_url=f"https://api.github.com/applications/{client_id}/grant",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        extra_params=extra_params or {},
        disconnect_fully_revokes=True,
        scope_metadata=BASE_SCOPE_METADATA,
    )
    return config, GitHubRevocationHandler()
