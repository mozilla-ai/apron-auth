"""Slack OAuth provider preset, identity handler, and revocation handler.

``disconnect_fully_revokes=False``: Slack's ``auth.revoke`` invalidates
the token but does not uninstall the app or remove workspace-level
authorization. For full grant removal, Slack requires uninstalling the
app from workspace settings (or org admin removal for org-wide apps).

The identity handler is scoped to the Sign-in-with-Slack OIDC flow
only; workspace-bot installs (no ``openid`` requested) intentionally
fall through so :meth:`OAuthClient.fetch_identity` raises
:class:`IdentityNotSupportedError` rather than calling Slack and
surfacing a confusing 401. ``openid.connect.userInfo`` is a tier-3
method (50+ requests/minute); apron-auth does not throttle library
side, so callers fanning out beyond that should add their own
rate-limiting.

References:
- https://api.slack.com/methods/auth.revoke
- https://docs.slack.dev/reference/methods/openid.connect.userInfo
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


_SLACK_USERINFO_URL = "https://slack.com/api/openid.connect.userInfo"
_SLACK_IDENTITY_HOST_SUFFIXES = ("slack.com",)
_SLACK_USER_ID_CLAIM = "https://slack.com/user_id"


def _has_openid_scope(config: ProviderConfig) -> bool:
    """Return True when ``openid`` appears in bot or user scopes.

    Slack's Sign-in-with-Slack flow can request ``openid`` either as a
    bot scope (pure SiwS) or as a user scope (combined bot + SiwS via
    Slack's ``user_scope`` query parameter, which the preset stores in
    ``extra_params["user_scope"]``). Either placement should enable
    identity inference.
    """
    if "openid" in config.scopes:
        return True
    user_scope = config.extra_params.get("user_scope", "")
    return any(scope.strip() == "openid" for scope in user_scope.split(","))


class SlackIdentityHandler:
    """Fetch identity fields from Slack's OIDC ``userInfo`` endpoint.

    The endpoint requires a Sign-in-with-Slack user token (issued when
    ``openid`` was in the granted scopes); it rejects bot tokens with
    HTTP 200 and ``ok=false``. Slack-namespaced claims use full-URL
    JSON keys (e.g. ``https://slack.com/user_id``) and are read as
    ordinary dict keys.
    """

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Slack SiwS user token."""
        del config
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    _SLACK_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Slack identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Slack identity response: {exc}") from exc

        if not isinstance(payload, dict):
            raise IdentityFetchError("Slack identity response was not a JSON object")

        # Slack returns 2xx with ``ok=false`` for auth/scope failures.
        if payload.get("ok") is False:
            error = payload.get("error") or "unknown_error"
            raise IdentityFetchError(f"Slack identity request failed: {error}")

        email_verified = None
        if "email_verified" in payload:
            email_verified = bool(payload.get("email_verified"))

        return IdentityProfile(
            subject=payload.get("sub"),
            email=payload.get("email"),
            email_verified=email_verified,
            name=payload.get("name"),
            username=payload.get(_SLACK_USER_ID_CLAIM),
            avatar_url=payload.get("picture"),
            raw=payload,
        )


class SlackRevocationHandler:
    """Slack token revocation via GET with token as query parameter."""

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token at Slack's revocation endpoint."""
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
        async with httpx.AsyncClient() as client:
            response = await client.get(
                config.revocation_url,
                params={"token": token},
            )
        if not response.is_success:
            return False
        data = response.json()
        return data.get("ok", False)


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Slack identity handler when SiwS is configured.

    Both ``authorize_url`` and ``token_url`` must match the Slack host
    suffix list, and ``openid`` must be among the configured bot or
    user scopes. Workspace-bot installs (no ``openid``) intentionally
    return ``None`` so :class:`IdentityNotSupportedError` surfaces
    cleanly instead of a 401 from Slack.
    """
    if not oauth_hosts_match(config, _SLACK_IDENTITY_HOST_SUFFIXES):
        return None
    if not _has_openid_scope(config):
        return None
    return SlackIdentityHandler()


IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="slack",
    resolver=maybe_identity_handler,
)


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    user_scopes: list[str] | None = None,
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Slack OAuth provider configuration.

    Slack's OAuth v2 uses separate query parameters for bot scopes
    (``scope``) and user scopes (``user_scope``). Pass ``user_scopes``
    to have the preset build the ``user_scope`` param automatically
    using the provider's scope separator.

    Slack's token exchange enforces a set-level rule: the request must
    ask for at least one bot scope **or** at least one user scope.
    The preset declares this on
    :attr:`ProviderConfig.required_scope_families` — one family per
    non-empty token family — so a consent picker can enforce the rule
    without Slack-specific knowledge.

    Raises:
        ValueError: If both ``scopes`` and ``user_scopes`` are empty.
    """
    if not scopes and not user_scopes:
        msg = "Slack OAuth requires at least one scope in scopes or user_scopes"
        raise ValueError(msg)

    scope_separator = ","

    merged_extra: dict[str, str] = dict(extra_params or {})
    if user_scopes:
        merged_extra["user_scope"] = scope_separator.join(user_scopes)

    required_scope_families: list[list[str]] = []
    if scopes:
        required_scope_families.append(list(scopes))
    if user_scopes:
        required_scope_families.append(list(user_scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://slack.com/oauth/v2/authorize",
        token_url="https://slack.com/api/oauth.v2.access",
        revocation_url="https://slack.com/api/auth.revoke",
        redirect_uri=redirect_uri,
        scopes=scopes,
        scope_separator=scope_separator,
        extra_params=merged_extra,
        disconnect_fully_revokes=False,
        required_scope_families=required_scope_families,
    )
    return config, SlackRevocationHandler()
