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

import httpx

from apron_auth._http_errors import http_failure
from apron_auth.errors import ConfigurationError, RevocationError
from apron_auth.models import (
    IdentityMaterial,
    IdentityProfile,
    Provider,
    ProviderConfig,
    TenancyContext,
    TokenEndpointAuthMethod,
)
from apron_auth.providers._identity_requests import fetch_identity_json
from apron_auth.providers._presets import Preset

logger = logging.getLogger(__name__)

# The endpoint that revokes a Notion access token.
NOTION_REVOCATION_URL = "https://api.notion.com/v1/oauth/revoke"

# What this provider's preset states, beside the values its caller passes.
_PRESET = Preset(
    provider=Provider.NOTION,
    authorize_url="https://api.notion.com/v1/oauth/authorize",
    token_url="https://api.notion.com/v1/oauth/token",
    revocation_url=NOTION_REVOCATION_URL,
    default_extra_params={"owner": "user"},
    token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
)

# The endpoint that returns the bot user of the access token, with its owner.
_NOTION_USERINFO_URL = "https://api.notion.com/v1/users/me"

# The Notion API version that the identity request names in its Notion-Version header.
_NOTION_VERSION_HEADER_VALUE = "2022-06-28"


class NotionIdentityHandler:
    """Fetch identity fields from Notion's ``/v1/users/me`` endpoint.

    Notion's ``/v1/users/me`` endpoint returns a bot user object. For
    external (public OAuth) integrations, ``bot.owner.type`` is
    ``"user"`` and owner-level identity fields can be mapped to
    ``IdentityProfile``. For internal integrations,
    ``bot.owner.type`` is ``"workspace"`` and end-user email is not
    available; this handler returns a workspace/bot-shaped identity.
    """

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Notion access token.

        Args:
            material: The token material to establish identity from.
            config: The provider configuration the tokens were issued under.

        Returns:
            The identity profile. External integrations yield owner-level
            person fields; internal integrations yield a workspace/bot
            identity. The workspace is surfaced as a single tenancy when
            present.

        Raises:
            IdentityFetchError: If the userinfo request fails or its
                response cannot be parsed.
                The failed request's error is not attached as its cause or context.
        """
        del config
        async with httpx.AsyncClient() as client:
            payload = await fetch_identity_json(
                client.get(
                    _NOTION_USERINFO_URL,
                    headers={
                        "Authorization": f"Bearer {material.access_token}",
                        "Notion-Version": _NOTION_VERSION_HEADER_VALUE,
                    },
                ),
                "Notion identity",
            )

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
            provider=Provider.NOTION,
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
        """Configure the handler.

        Args:
            client: An optional caller-owned client to send revocation
                requests through; a fresh client is used per request when
                omitted.
        """
        self._client = client

    async def _send(
        self,
        client: httpx.AsyncClient,
        token: str,
        revocation_url: str,
        config: ProviderConfig,
    ) -> bool:
        """Send the revocation request and return success status.

        Args:
            client: The HTTP client to send the request through.
            token: The token to revoke.
            revocation_url: The endpoint to POST the revocation to.
            config: The provider configuration supplying client credentials.

        Returns:
            ``True`` on 200 (revoked) or 400 (already invalid — idempotent),
            ``False`` on any other status.

        Raises:
            RevocationError: If the request fails to reach the endpoint.
                The failed request's error is not attached as its cause or context.
        """
        auth = config.basic_auth()
        try:
            response = await client.post(
                revocation_url,
                json={"token": token},
                # Pass None (not USE_CLIENT_DEFAULT) for a public client, so an injected client's own
                # auth flow is not applied to the server-supplied revocation URL.
                auth=auth,  # ty: ignore[invalid-argument-type]
            )
        except httpx.RequestError as exc:
            failure = http_failure(exc)
        else:
            if response.status_code in (200, 400):
                return True
            logger.warning(
                "Notion revocation returned unexpected status %d",
                response.status_code,
            )
            return False
        # NOTE: The caught error holds the request, which carries the token, so this error must not reference it.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise RevocationError(f"Failed to revoke Notion token: {failure.description}", kind=failure.kind)

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a Notion access token.

        Args:
            token: The token to revoke.
            config: The provider configuration supplying the revocation URL
                and client credentials.

        Returns:
            ``True`` when the endpoint reports the token revoked or already
            invalid.

        Raises:
            ConfigurationError: If ``config`` has no revocation URL.
            RevocationError: If the request fails to reach the endpoint.
                The failed request's error is not attached as its cause or context.
        """
        if config.revocation_url is None:
            msg = "the provider configuration carries no revocation endpoint"
            raise ConfigurationError(msg)
        revocation_url = config.revocation_url
        if self._client is not None:
            return await self._send(self._client, token, revocation_url, config)
        async with httpx.AsyncClient() as client:
            return await self._send(client, token, revocation_url, config)


def preset(
    client_id: str,
    client_secret: str,
    *,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> ProviderConfig:
    """Create a Notion OAuth provider configuration.

    Notion uses client_secret_basic auth. Revocation targets
    https://api.notion.com/v1/oauth/revoke, set as
    ``config.revocation_url`` so that ``OAuthClient.revoke_token()``
    can dispatch to the returned :class:`NotionRevocationHandler`.

    Args:
        client_id: The OAuth client identifier.
        client_secret: The OAuth client secret.
        scopes: The scopes to request.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters; merged over
            the ``owner=user`` default.

    Returns:
        The provider configuration. The client resolves this provider's revocation handler
        from it.
    """
    return _PRESET.config(client_id, client_secret, scopes=scopes, redirect_uri=redirect_uri, extra_params=extra_params)
