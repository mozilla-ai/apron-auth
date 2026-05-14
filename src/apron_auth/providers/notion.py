"""Notion OAuth provider preset and revocation handler.

``disconnect_fully_revokes=False``: Notion documents
``POST /v1/oauth/revoke`` for token invalidation, but does not explicitly
confirm that revoke removes the workspace installation/grant. Until
provider docs or end-to-end verification confirm full grant removal,
this preset keeps the conservative tier-3 value.

References:
- https://developers.notion.com/reference/revoke-token
- https://developers.notion.com/docs/authorization
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError, RevocationError
from apron_auth.models import IdentityProfile, ProviderConfig, TenancyContext
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler

logger = logging.getLogger(__name__)

NOTION_REVOCATION_URL = "https://api.notion.com/v1/oauth/revoke"
_NOTION_USERINFO_URL = "https://api.notion.com/v1/users/me"
_NOTION_VERSION_HEADER_VALUE = "2022-06-28"
_NOTION_IDENTITY_HOST_SUFFIXES = ("api.notion.com",)


class NotionIdentityHandler:
    """Fetch identity fields from Notion's ``/v1/users/me`` endpoint.

    Notion's ``/v1/users/me`` endpoint returns a bot user object. For
    external (public OAuth) integrations, ``bot.owner.type`` is
    ``"user"`` and owner-level identity fields can be mapped to
    ``IdentityProfile``. For internal integrations,
    ``bot.owner.type`` is ``"workspace"`` and end-user email is not
    available; this handler returns a workspace/bot-shaped identity.
    """

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Notion access token."""
        del config
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    _NOTION_USERINFO_URL,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Notion-Version": _NOTION_VERSION_HEADER_VALUE,
                    },
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Notion identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Notion identity response: {exc}") from exc

        bot = payload.get("bot") if isinstance(payload, dict) else None
        owner = bot.get("owner") if isinstance(bot, dict) else None

        subject: str | None = None
        email: str | None = None
        name: str | None = None
        username: str | None = None

        if isinstance(owner, dict) and owner.get("type") == "user":
            owner_user = owner.get("user")
            if isinstance(owner_user, dict):
                subject = owner_user.get("id")
                name = owner_user.get("name")
                person = owner_user.get("person")
                if isinstance(person, dict):
                    email = person.get("email")
        elif isinstance(owner, dict) and owner.get("type") == "workspace":
            bot_id = payload.get("id") if isinstance(payload, dict) else None
            if isinstance(bot_id, str) and bot_id:
                subject = f"bot:{bot_id}"
            if isinstance(bot, dict):
                username = bot.get("workspace_name")

        avatar_url = payload.get("avatar_url") if isinstance(payload, dict) else None

        # ``/v1/users/me`` exposes ``workspace_id`` and ``workspace_name``
        # on the bot object. Notion does not surface a workspace
        # ``domain`` on this endpoint (workspaces have no public host),
        # so ``TenancyContext.domain`` is intentionally ``None`` for
        # this provider. ``workspace_icon`` is only returned by the
        # OAuth token-grant response, not ``/v1/users/me``; capture it
        # at exchange time on the consumer side if needed.
        # ``workspace_name`` may itself be missing on rare token shapes
        # (e.g. legacy internal-integration grants); a missing ``name``
        # surfaces as ``None`` per the :class:`TenancyContext` contract,
        # so the entry is still emitted as long as ``workspace_id`` —
        # the canonical anchor — is present.
        tenancies: tuple[TenancyContext, ...] = ()
        if isinstance(bot, dict):
            workspace_id = bot.get("workspace_id")
            if workspace_id:
                tenancies = (
                    TenancyContext(
                        id=workspace_id,
                        name=bot.get("workspace_name"),
                    ),
                )

        return IdentityProfile(
            provider="notion",
            subject=subject,
            email=email,
            email_verified=None,
            name=name,
            username=username,
            avatar_url=avatar_url,
            tenancies=tenancies,
            raw=payload,
        )


class NotionRevocationHandler:
    """Notion token revocation via POST with JSON body and Basic auth.

    Notion's revoke endpoint returns 200 on success and 400 when the token
    is already invalid; both are treated as successful (idempotent) outcomes.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def _send(
        self,
        client: httpx.AsyncClient,
        token: str,
        revocation_url: str,
        config: ProviderConfig,
    ) -> bool:
        """Send the revocation request and return success status."""
        try:
            response = await client.post(
                revocation_url,
                json={"token": token},
                auth=(config.client_id, config.client_secret.get_secret_value()),
            )
        except httpx.RequestError as exc:
            raise RevocationError(str(exc)) from exc
        if response.status_code in (200, 400):
            return True
        logger.warning(
            "Notion revocation returned unexpected status %d",
            response.status_code,
        )
        return False

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a Notion access token."""
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
        revocation_url = config.revocation_url
        if self._client is not None:
            return await self._send(self._client, token, revocation_url, config)
        async with httpx.AsyncClient() as client:
            return await self._send(client, token, revocation_url, config)


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Notion identity handler when config matches Notion hosts."""
    if oauth_hosts_match(config, _NOTION_IDENTITY_HOST_SUFFIXES):
        return NotionIdentityHandler()
    return None


IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="notion",
    resolver=maybe_identity_handler,
)


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Notion OAuth provider configuration.

    Notion uses client_secret_basic auth. Revocation targets
    https://api.notion.com/v1/oauth/revoke, set as
    ``config.revocation_url`` so that ``OAuthClient.revoke_token()``
    can dispatch to the returned :class:`NotionRevocationHandler`.
    """
    defaults = {"owner": "user"}
    if extra_params:
        defaults.update(extra_params)

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://api.notion.com/v1/oauth/authorize",
        token_url="https://api.notion.com/v1/oauth/token",
        revocation_url=NOTION_REVOCATION_URL,
        redirect_uri=redirect_uri,
        scopes=scopes,
        token_endpoint_auth_method="client_secret_basic",
        extra_params=defaults,
        disconnect_fully_revokes=False,
    )
    return config, NotionRevocationHandler()
