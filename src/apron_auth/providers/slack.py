"""Slack OAuth provider preset, identity handler, and revocation handler.

``disconnect_fully_revokes=False``: Slack's ``auth.revoke`` invalidates
the token but does not uninstall the app or remove workspace-level
authorization. For full grant removal, Slack requires uninstalling the
app from workspace settings (or org admin removal for org-wide apps).

The identity handler covers two distinct Slack OAuth flows behind a
single resolver registration:

- Sign-in-with-Slack (``openid`` in scopes) → OIDC ``userInfo`` for
  full person identity plus single-workspace tenancy.
- Workspace-bot installation (no ``openid``) → ``team.info`` (with
  ``auth.test`` as the universal fallback) for workspace tenancy
  only; person fields stay ``None`` because workspace-bot tokens do
  not represent a single human.

``openid.connect.userInfo`` is a tier-3 method (50+ requests/minute);
``team.info`` and ``auth.test`` are likewise rate-limited per Slack's
tier scheme. apron-auth does not throttle library-side, so callers
fanning out heavily should add their own rate-limiting.

References:
- https://api.slack.com/methods/auth.revoke
- https://docs.slack.dev/reference/methods/auth.test
- https://docs.slack.dev/reference/methods/openid.connect.userInfo
- https://docs.slack.dev/reference/methods/team.info
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig, TenancyContext
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


_SLACK_AUTH_TEST_URL = "https://slack.com/api/auth.test"
_SLACK_HOST_SUFFIX = ".slack.com"
_SLACK_IDENTITY_HOST_SUFFIXES = ("slack.com",)
_SLACK_TEAM_DOMAIN_CLAIM = "https://slack.com/team_domain"
_SLACK_TEAM_ID_CLAIM = "https://slack.com/team_id"
_SLACK_TEAM_INFO_URL = "https://slack.com/api/team.info"
_SLACK_TEAM_NAME_CLAIM = "https://slack.com/team_name"
_SLACK_USERINFO_URL = "https://slack.com/api/openid.connect.userInfo"
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


def _parse_team_domain_from_url(url: str | None) -> str | None:
    """Extract the workspace subdomain from a Slack workspace URL.

    Slack's ``auth.test`` returns a workspace URL like
    ``https://kraneflannel.slack.com/`` whose host's leading label is
    the workspace's ``team_domain``. ``team.info`` exposes the domain
    directly, so this helper is only used on the ``auth.test``
    fallback path. Returns ``None`` for missing input or any host that
    does not end in ``.slack.com`` (e.g. Enterprise Grid org URLs on
    ``*.enterprise.slack.com`` still match, but unrelated hosts do
    not), preferring an absent value over a guess.
    """
    if not url:
        return None
    host = urlparse(url).hostname
    if not host or not host.endswith(_SLACK_HOST_SUFFIX):
        return None
    label = host[: -len(_SLACK_HOST_SUFFIX)]
    # Empty (host was exactly "slack.com") or further-qualified hosts
    # without a clear workspace label are not safe to surface as a
    # ``team_domain``; the leading label must be a single segment.
    if not label or "." in label:
        return None
    return label


class SlackIdentityHandler:
    """Fetch identity fields from the Slack flow indicated by config.

    Slack has two distinct OAuth shapes that both produce useful
    identity data:

    - Sign-in-with-Slack (``openid`` in scopes) issues a user token
      and exposes a person-shaped OIDC ``userInfo`` response with
      Slack-namespaced ``team_*`` claims using full-URL JSON keys
      (e.g. ``https://slack.com/user_id``) read as ordinary dict
      keys.
    - Workspace-bot installation (no ``openid``) issues bot/user
      tokens with workspace scopes; ``team.info`` is the rich source
      of workspace identity (``team:read``-gated) and ``auth.test``
      is the universal fallback when ``team:read`` was not granted.

    Both flows are handled by a single registration and a single
    handler that branches internally on ``openid`` presence. The
    alternative — registering two handlers — would break the
    registry's implicit 1:1 provider→handler assumption and force
    :func:`apron_auth.providers.identity.infer_identity_handler` to
    special-case Slack to disambiguate. Internal branching keeps the
    registry contract clean and mirrors how Slack itself layers
    user-vs-workspace identity over the same OAuth surface. Tokens
    granted both ``openid`` and bot scopes route to the OIDC path
    because it is strictly richer (full person identity plus
    tenancy).

    For workspace-bot tokens, person-identity fields
    (:attr:`IdentityProfile.subject`, ``email``, ``name``, ``username``,
    ``avatar_url``) are all ``None`` by design. The token does not
    represent a human: the bot user is not the installer, and the
    registered Slack app is not either. Synthesising a ``subject``
    from ``bot_user_id`` would conflate runtime bot identity with
    installer identity. Consumers that need installer identity should
    use Sign-in-with-Slack alongside the workspace-bot install.
    """

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields from the appropriate Slack flow."""
        if _has_openid_scope(config):
            return await self._fetch_via_oidc(access_token)
        return await self._fetch_workspace_only(access_token)

    async def _fetch_via_oidc(self, access_token: str) -> IdentityProfile:
        """Fetch identity using the Sign-in-with-Slack OIDC userInfo endpoint."""
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

        # Sign-in-with-Slack tokens are single-workspace, so a populated
        # ``team_id`` always maps to exactly one TenancyContext. Slack
        # reliably returns ``team_name`` and ``team_domain`` alongside
        # ``team_id`` for SiwS tokens, but the model contract allows
        # either to be ``None``; gating on ``team_id`` (the canonical
        # anchor) keeps the entry meaningful even on unexpected shapes.
        team_id = payload.get(_SLACK_TEAM_ID_CLAIM)
        tenancies: tuple[TenancyContext, ...] = ()
        if team_id:
            tenancies = (
                TenancyContext(
                    id=team_id,
                    name=payload.get(_SLACK_TEAM_NAME_CLAIM),
                    domain=payload.get(_SLACK_TEAM_DOMAIN_CLAIM),
                ),
            )

        return IdentityProfile(
            subject=payload.get("sub"),
            email=payload.get("email"),
            email_verified=email_verified,
            name=payload.get("name"),
            username=payload.get(_SLACK_USER_ID_CLAIM),
            avatar_url=payload.get("picture"),
            tenancies=tenancies,
            raw=payload,
        )

    async def _fetch_workspace_only(self, access_token: str) -> IdentityProfile:
        """Fetch workspace tenancy for a non-OIDC (workspace-bot) token.

        Endpoint priority is fixed and intentional:

        1. ``team.info`` — preferred. Returns ``id`` / ``name`` /
           ``domain`` plus Enterprise Grid context (``enterprise_id``,
           ``enterprise_name``) directly. Costs the ``team:read`` bot
           scope, which the consumer may or may not have requested.
        2. ``auth.test`` — universal fallback. Costs no extra scope
           and works on any valid token, but only returns ``team``
           (name) and ``team_id`` directly; the workspace ``domain``
           must be parsed from the response's ``url`` host
           (``https://kraneflannel.slack.com/`` → ``kraneflannel``).

        ``auth.test`` is reached only when ``team.info`` returns
        ``ok=false`` with ``error="missing_scope"``. Other ``ok=false``
        errors (``invalid_auth``, ``token_revoked``, etc.) fail fast
        so real auth problems are not papered over by the fallback.

        Enterprise Grid responses are surfaced as a single
        :class:`TenancyContext` whose ``raw`` carries the team-level
        Slack payload (which itself includes ``enterprise_id`` and
        ``enterprise_name`` when present). Multi-team Enterprise Grid
        — populating one ``TenancyContext`` per accessible team — is
        deliberately deferred until a concrete consumer use case
        lands; the single-tenant assumption documented here must be
        revisited at that point rather than quietly invalidated.
        """
        # Reuse one client for the optional fallback to keep the
        # connection pool warm across both calls.
        async with httpx.AsyncClient() as client:
            team_info_payload = await self._slack_post(client, _SLACK_TEAM_INFO_URL, access_token, "team.info")
            if team_info_payload.get("ok"):
                return _build_workspace_profile_from_team_info(team_info_payload)

            error = team_info_payload.get("error") or "unknown_error"
            if error != "missing_scope":
                raise IdentityFetchError(f"Slack team.info request failed: {error}")

            auth_test_payload = await self._slack_post(client, _SLACK_AUTH_TEST_URL, access_token, "auth.test")

        if not auth_test_payload.get("ok"):
            error = auth_test_payload.get("error") or "unknown_error"
            raise IdentityFetchError(f"Slack auth.test request failed: {error}")

        return _build_workspace_profile_from_auth_test(auth_test_payload)

    @staticmethod
    async def _slack_post(
        client: httpx.AsyncClient,
        url: str,
        access_token: str,
        endpoint_label: str,
    ) -> dict[str, Any]:
        """POST to a Slack Web API method and return the JSON object payload."""
        try:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Slack {endpoint_label}: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Slack {endpoint_label} response: {exc}") from exc

        if not isinstance(payload, dict):
            raise IdentityFetchError(f"Slack {endpoint_label} response was not a JSON object")
        return payload


def _build_workspace_profile_from_auth_test(payload: dict[str, Any]) -> IdentityProfile:
    """Build a workspace-only IdentityProfile from an ``auth.test`` payload.

    ``team_id`` is the canonical anchor — the tenancy entry is emitted
    only when it is populated. ``domain`` is derived from the
    ``url`` host's leading label and may be ``None`` when the host is
    not a recognisable Slack workspace URL. Person-identity fields
    stay ``None``; see :class:`SlackIdentityHandler` for why.
    """
    team_id = payload.get("team_id")
    tenancies: tuple[TenancyContext, ...] = ()
    if team_id:
        tenancies = (
            TenancyContext(
                id=team_id,
                name=payload.get("team"),
                domain=_parse_team_domain_from_url(payload.get("url")),
                raw=payload,
            ),
        )
    return IdentityProfile(tenancies=tenancies, raw=payload)


def _build_workspace_profile_from_team_info(payload: dict[str, Any]) -> IdentityProfile:
    """Build a workspace-only IdentityProfile from a ``team.info`` payload.

    ``team.info`` nests workspace fields under the ``team`` key.
    ``id`` is the canonical anchor — the tenancy entry is emitted
    only when it is populated. Enterprise Grid context
    (``enterprise_id`` / ``enterprise_name``) flows through the
    ``team`` payload onto ``TenancyContext.raw`` without being lifted
    to dedicated fields, preserving the single-tenancy contract.
    Person-identity fields stay ``None``; see
    :class:`SlackIdentityHandler` for why.
    """
    team = payload.get("team")
    team_payload: dict[str, Any] = team if isinstance(team, dict) else {}
    team_id = team_payload.get("id")
    tenancies: tuple[TenancyContext, ...] = ()
    if team_id:
        tenancies = (
            TenancyContext(
                id=team_id,
                name=team_payload.get("name"),
                domain=team_payload.get("domain"),
                raw=team_payload,
            ),
        )
    return IdentityProfile(tenancies=tenancies, raw=payload)


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
    """Return the Slack identity handler when config matches Slack hosts.

    Both ``authorize_url`` and ``token_url`` must match the Slack host
    suffix list. The handler itself branches on ``openid`` presence at
    fetch time — Sign-in-with-Slack and workspace-bot tokens are both
    handled — so resolution is purely host-based here. The single
    handler / single registration design is documented on
    :class:`SlackIdentityHandler`.
    """
    if not oauth_hosts_match(config, _SLACK_IDENTITY_HOST_SUFFIXES):
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
