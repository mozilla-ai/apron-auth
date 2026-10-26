"""Slack OAuth provider preset, identity handler, and revocation handler.

``disconnect_fully_revokes=False``: Slack's ``auth.revoke`` invalidates
the token but does not uninstall the app or remove workspace-level
authorization. For full grant removal, Slack requires uninstalling the
app from workspace settings (or org admin removal for org-wide apps).

Slack serves Sign in with Slack and a workspace installation from separate
endpoints, and says each set of scopes must be requested in its own OAuth
flow. :func:`sign_in_preset` configures the first and :func:`preset` the
second. Only Slack's OpenID token endpoint returns an ID token, so only a
Sign in with Slack response can carry the nonce the request sent.

The identity handler covers both flows, selected by the token endpoint the
configuration names:

- Sign in with Slack → OIDC ``userInfo`` for full person identity plus
  single-workspace tenancy.
- Workspace-bot installation → ``team.info`` (with ``auth.test`` as the
  universal fallback) for workspace tenancy only; person fields stay
  ``None`` because workspace-bot tokens do not represent a single human.

``openid.connect.userInfo`` is a tier-3 method (50+ requests/minute);
``team.info`` and ``auth.test`` are likewise rate-limited per Slack's
tier scheme. apron-auth does not throttle library-side, so callers
fanning out heavily should add their own rate-limiting.

References:
- https://api.slack.com/methods/auth.revoke
- https://docs.slack.dev/authentication/sign-in-with-slack/
- https://docs.slack.dev/reference/methods/openid.connect.token
- https://docs.slack.dev/reference/methods/auth.test
- https://docs.slack.dev/reference/methods/openid.connect.userInfo
- https://docs.slack.dev/reference/methods/team.info
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from apron_auth._authorization_params import authorization_query, scope_param, sent_scope_words
from apron_auth._http_errors import http_failure
from apron_auth._json_body import decode_json_body
from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    IdentityScopeNotGrantedError,
    RevocationError,
)
from apron_auth.models import (
    IdentityMaterial,
    IdentityProfile,
    Provider,
    ProviderConfig,
    ScopeMetadata,
    TenancyContext,
)
from apron_auth.providers._identity_requests import fetch_identity_json
from apron_auth.providers._presets import Preset
from apron_auth.scopes import scope_words

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler


# The scope the sign-in preset always requests, with the label a consent screen shows.
SIGN_IN_SCOPE_METADATA = [
    ScopeMetadata(
        scope="openid",
        label="OpenID",
        description="Authenticate your Slack identity",
        access_type="read",
        required=True,
    )
]

# The endpoint that identifies the token's user and workspace.
_SLACK_AUTH_TEST_URL = "https://slack.com/api/auth.test"

# The suffix of a workspace host, such as acme.slack.com.
_SLACK_HOST_SUFFIX = ".slack.com"

# The error code Slack returns when the token lacks a scope the method needs.
_SLACK_MISSING_SCOPE_ERROR = "missing_scope"

# The authorize endpoint for Sign in with Slack.
_SLACK_OPENID_AUTHORIZE_URL = "https://slack.com/openid/connect/authorize"

# The issuer Slack states in its OpenID discovery document.
_SLACK_OPENID_ISSUER = "https://slack.com"

# The token endpoint for Sign in with Slack, which is the only Slack endpoint that returns an ID token.
_SLACK_OPENID_TOKEN_URL = "https://slack.com/api/openid.connect.token"

# The endpoint that revokes a token.
_SLACK_REVOKE_URL = "https://slack.com/api/auth.revoke"

# The scope that asks Slack for an ID token. Slack issues it to a user token only.
_SLACK_SIGN_IN_SCOPE = "openid"

# The two presets sit last because they read the endpoint constants above, and are A-Z between themselves.

# What the workspace-install preset states, beside the values its caller passes.
# NOTE: The required scope families name the caller's own scopes, so they are stated per call.
_INSTALL_PRESET = Preset(
    provider=Provider.SLACK,
    authorize_url="https://slack.com/oauth/v2/authorize",
    token_url="https://slack.com/api/oauth.v2.access",
    revocation_url=_SLACK_REVOKE_URL,
)

# What the Sign in with Slack preset states, beside the values its caller passes.
_SIGN_IN_PRESET = Preset(
    provider=Provider.SLACK,
    authorize_url=_SLACK_OPENID_AUTHORIZE_URL,
    token_url=_SLACK_OPENID_TOKEN_URL,
    revocation_url=_SLACK_REVOKE_URL,
    issuer=_SLACK_OPENID_ISSUER,
    required_scope_families=[[_SLACK_SIGN_IN_SCOPE]],
    scope_metadata=SIGN_IN_SCOPE_METADATA,
)

# The scopes Slack's OpenID discovery document states for Sign in with Slack.
_SLACK_SIGN_IN_SCOPES = frozenset({"email", "openid", "profile"})

# The error codes Slack returns, with HTTP 200 and ``ok=false``, for its own outages and rate limits.
_SLACK_TRANSIENT_ERRORS = frozenset(
    {"fatal_error", "internal_error", "ratelimited", "request_timeout", "service_unavailable"}
)

# The userinfo claim that holds the workspace domain.
_SLACK_TEAM_DOMAIN_CLAIM = "https://slack.com/team_domain"

# The userinfo claim that holds the workspace ID.
_SLACK_TEAM_ID_CLAIM = "https://slack.com/team_id"

# The endpoint that returns the workspace of the token.
_SLACK_TEAM_INFO_URL = "https://slack.com/api/team.info"

# The userinfo claim that holds the workspace name.
_SLACK_TEAM_NAME_CLAIM = "https://slack.com/team_name"

# The OpenID userinfo endpoint for Sign in with Slack.
_SLACK_USERINFO_URL = "https://slack.com/api/openid.connect.userInfo"

# The userinfo claim that holds the Slack user ID.
_SLACK_USER_ID_CLAIM = "https://slack.com/user_id"


def _sent_authorization_params(config: ProviderConfig) -> dict[str, str | list[str]]:
    """Return the authorization-request parameters ``config`` sends.

    Slack carries bot scopes and user scopes in separate parameters, so which flow a request asks
    for is read from the parameters themselves rather than from the configured scopes alone.

    Args:
        config: The provider configuration the request is built from.

    Returns:
        The parameters, with each one's value or values.
    """
    return authorization_query(config, scope_param(config))


def _extra_params_without_scope(extra_params: dict[str, str] | None) -> dict[str, str]:
    """Return the extra authorization parameters a preset was given, refusing one that sets the scope.

    An extra parameter named ``scope`` replaces the scope parameter a preset builds from its own
    scope arguments, so the two cannot both be honored.

    Args:
        extra_params: The extra authorization-request parameters, if any.

    Returns:
        The parameters, as a dict of their own.

    Raises:
        ValueError: If the parameters set ``scope``.
    """
    without_scope = dict(extra_params or {})
    if "scope" in without_scope:
        msg = "Slack scopes are set through this preset's scope parameters, so extra_params cannot set scope"
        raise ConfigurationError(msg)
    return without_scope


def _is_sign_in_flow(config: ProviderConfig) -> bool:
    """Return True when the configuration signs a person in rather than installing a workspace app.

    Slack returns an ID token from its OpenID token endpoint alone, so a token from any other
    Slack endpoint stands for a workspace and not for a person. An endpoint that differs only in
    host case or in a default port names the same endpoint.

    Args:
        config: The provider configuration to inspect.

    Returns:
        ``True`` when the configuration takes its tokens from Slack's OpenID token endpoint.
    """
    return httpx.URL(config.token_url) == httpx.URL(_SLACK_OPENID_TOKEN_URL)


def _parse_team_domain_from_url(url: str | None) -> str | None:
    """Extract the workspace subdomain from a Slack workspace URL.

    Slack's ``auth.test`` returns a workspace URL like
    ``https://kraneflannel.slack.com/`` whose host's leading label is
    the workspace's ``team_domain``. ``team.info`` exposes the domain
    directly, so this helper is only used on the ``auth.test``
    fallback path.

    Preferring an absent value over a guess keeps the contract honest
    when the URL shape is ambiguous.

    Args:
        url: The workspace URL to parse, if any.

    Returns:
        The workspace ``team_domain`` (the host's leading label), or
        ``None`` for any of:

        - missing input;
        - a host that does not end in ``.slack.com``;
        - a host that does end in ``.slack.com`` but whose leading label
          is empty or itself multi-segment — Enterprise Grid org URLs
          like ``myorg.enterprise.slack.com`` pass the suffix check yet
          surface no single workspace ``team_domain``.
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


def _slack_failure_kind(error: str) -> FailureKind:
    """Return the kind of a Slack ``ok=false`` answer.

    An outage or a rate limit may pass later. Every other code is a rejection.
    """
    return FailureKind.SERVER_ERROR if error in _SLACK_TRANSIENT_ERRORS else FailureKind.REJECTED


class SlackIdentityHandler:
    """Fetch identity fields from the Slack flow indicated by config.

    Slack has two distinct OAuth shapes that both produce useful
    identity data:

    - Sign in with Slack issues a user token and exposes a
      person-shaped OIDC ``userInfo`` response with Slack-namespaced
      ``team_*`` claims using full-URL JSON keys
      (e.g. ``https://slack.com/user_id``) read as ordinary dict
      keys.
    - Workspace-bot installation issues bot/user tokens with
      workspace scopes; ``team.info`` is the rich source of workspace
      identity (``team:read``-gated) and ``auth.test`` is the
      universal fallback when ``team:read`` was not granted.

    One handler serves both flows and branches internally on the token
    endpoint the configuration names, because a provider has one
    identity handler and the two flows are one provider. Slack serves
    each flow from its own endpoints, so the endpoint states which
    identity a token carries and a scope word does not.

    For workspace-bot tokens, person-identity fields
    (:attr:`IdentityProfile.subject`, ``email``, ``name``, ``username``,
    ``avatar_url``) are all ``None`` by design. The token does not
    represent a human: the bot user is not the installer, and the
    registered Slack app is not either. Synthesising a ``subject``
    from ``bot_user_id`` would conflate runtime bot identity with
    installer identity. Consumers that need installer identity should
    use Sign-in-with-Slack alongside the workspace-bot install.
    """

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields from the appropriate Slack flow.

        Args:
            material: The token material to establish identity from.
            config: The provider configuration; its token endpoint selects the
                Sign in with Slack (OIDC) or workspace-bot identity path.

        Returns:
            The identity profile: full person identity plus a
            single-workspace tenancy for Sign-in-with-Slack, or workspace
            tenancy only for a workspace-bot token.

        Raises:
            ConfigurationError: If the configuration's token endpoint and its
                requested scopes name different flows, or if it sends a scope
                parameter the named flow does not use.
            IdentityScopeNotGrantedError: If the Sign-in-with-Slack token
                lacks a scope the userInfo endpoint requires.
            IdentityFetchError: If the selected Slack request fails, its
                response cannot be parsed, or Slack reports an error.
        """
        access_token = material.access_token
        sign_in_endpoint = _is_sign_in_flow(config)
        sent = _sent_authorization_params(config)
        separator = config.scope_separator
        sends_sign_in_scope = _SLACK_SIGN_IN_SCOPE in sent_scope_words(sent, "scope", separator)
        if sign_in_endpoint and not sends_sign_in_scope:
            msg = (
                "A Slack configuration naming Slack's OpenID token endpoint must ask for the openid scope, "
                "because without it Slack returns no ID token and no nonce is sent or checked. "
                "Build it with sign_in_preset."
            )
            raise ConfigurationError(msg)
        if sign_in_endpoint and "user_scope" in sent:
            msg = (
                "A Slack configuration naming Slack's OpenID token endpoint must send no user_scope "
                "parameter, because Slack grants its user scopes from its own endpoints and in a flow "
                "of their own. Build it with sign_in_preset."
            )
            raise ConfigurationError(msg)
        if not sign_in_endpoint and (
            sends_sign_in_scope or _SLACK_SIGN_IN_SCOPE in sent_scope_words(sent, "user_scope", separator)
        ):
            msg = (
                "A Slack configuration asking for the openid scope must name Slack's OpenID token endpoint "
                "exactly, because no other Slack endpoint returns an ID token. Build it with sign_in_preset."
            )
            raise ConfigurationError(msg)
        if sign_in_endpoint:
            return await self._fetch_via_oidc(access_token)
        return await self._fetch_workspace_only(access_token)

    async def _fetch_via_oidc(self, access_token: str) -> IdentityProfile:
        """Fetch identity using the Sign-in-with-Slack OIDC userInfo endpoint.

        Args:
            access_token: The bearer access token for the userInfo request.

        Returns:
            The person identity profile with a single-workspace tenancy.

        Raises:
            IdentityScopeNotGrantedError: If Slack reports ``missing_scope``.
            IdentityFetchError: If the request fails, its response cannot be
                parsed, or Slack reports another ``ok=false`` error.
                The failed request's error is not attached as its cause or context.
        """
        async with httpx.AsyncClient() as client:
            payload = await fetch_identity_json(
                client.post(
                    _SLACK_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                ),
                "Slack identity",
            )

        if not isinstance(payload, dict):
            msg = "Slack identity response was not a JSON object"
            raise IdentityFetchError(msg, kind=FailureKind.REFUSED)

        # Slack returns 2xx with ``ok=false`` for auth/scope failures.
        if payload.get("ok") is False:
            error = payload.get("error") or "unknown_error"
            if error == _SLACK_MISSING_SCOPE_ERROR:
                raise IdentityScopeNotGrantedError(f"Slack identity request failed: {error}")
            raise IdentityFetchError(f"Slack identity request failed: {error}", kind=_slack_failure_kind(error))

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
            provider=Provider.SLACK,
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

        Args:
            access_token: The bearer access token for the workspace lookup.

        Returns:
            A workspace-only identity profile; person-identity fields are
            ``None``.

        Raises:
            IdentityFetchError: If ``team.info`` fails for a reason other
                than a missing scope, the ``auth.test`` fallback fails, or a
                response cannot be parsed.
        """
        # Reuse one client for the optional fallback to keep the
        # connection pool warm across both calls.
        async with httpx.AsyncClient() as client:
            team_info_payload = await self._slack_post(client, _SLACK_TEAM_INFO_URL, access_token, "team.info")
            if team_info_payload.get("ok"):
                return _build_workspace_profile_from_team_info(team_info_payload)

            error = team_info_payload.get("error") or "unknown_error"
            # NOTE: auth.test recovers from missing_scope here, so it must not raise IdentityScopeNotGrantedError.
            if error != _SLACK_MISSING_SCOPE_ERROR:
                raise IdentityFetchError(f"Slack team.info request failed: {error}", kind=_slack_failure_kind(error))

            auth_test_payload = await self._slack_post(client, _SLACK_AUTH_TEST_URL, access_token, "auth.test")

        if not auth_test_payload.get("ok"):
            error = auth_test_payload.get("error") or "unknown_error"
            raise IdentityFetchError(f"Slack auth.test request failed: {error}", kind=_slack_failure_kind(error))

        return _build_workspace_profile_from_auth_test(auth_test_payload)

    @staticmethod
    async def _slack_post(
        client: httpx.AsyncClient,
        url: str,
        access_token: str,
        endpoint_label: str,
    ) -> dict[str, Any]:
        """POST to a Slack Web API method and return the JSON object payload.

        Args:
            client: The HTTP client to send the request through.
            url: The Slack Web API method URL to POST to.
            access_token: The bearer access token for the request.
            endpoint_label: A short method label used in error messages.

        Returns:
            The response payload as a JSON object.

        Raises:
            IdentityFetchError: If the request fails, its response cannot be
                parsed, or it is not a JSON object.
                The failed request's error is not attached as its cause or context.
        """
        payload = await fetch_identity_json(
            client.post(url, headers={"Authorization": f"Bearer {access_token}"}),
            f"Slack {endpoint_label}",
        )

        if not isinstance(payload, dict):
            msg = f"Slack {endpoint_label} response was not a JSON object"
            raise IdentityFetchError(msg, kind=FailureKind.REFUSED)
        return payload


def _build_workspace_profile_from_auth_test(payload: dict[str, Any]) -> IdentityProfile:
    """Build a workspace-only IdentityProfile from an ``auth.test`` payload.

    ``team_id`` is the canonical anchor — the tenancy entry is emitted
    only when it is populated. ``domain`` is derived from the
    ``url`` host's leading label and may be ``None`` when the host is
    not a recognisable Slack workspace URL. Person-identity fields
    stay ``None``; see :class:`SlackIdentityHandler` for why.

    Args:
        payload: The parsed ``auth.test`` response.

    Returns:
        A workspace-only identity profile, with a tenancy only when the
        payload carries a ``team_id``.
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
    return IdentityProfile(provider=Provider.SLACK, tenancies=tenancies, raw=payload)


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

    Args:
        payload: The parsed ``team.info`` response.

    Returns:
        A workspace-only identity profile, with a tenancy only when the
        nested team carries an ``id``.
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
    return IdentityProfile(provider=Provider.SLACK, tenancies=tenancies, raw=payload)


class SlackRevocationHandler:
    """Revoke Slack tokens at the ``auth.revoke`` endpoint.

    Slack rejects tokens sent as a URL query parameter for apps
    created after 2021-02-24, so the token is sent in the
    ``Authorization: Bearer`` header of a POST rather than as a
    query-string parameter.
    """

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token at Slack's revocation endpoint.

        Args:
            token: The token to revoke.
            config: The provider configuration supplying the revocation URL.

        Returns:
            ``True`` when Slack confirms revocation with the boolean ``"ok": true``.
            ``False`` for an error status, or for an ``ok`` value that is missing or anything other than ``true``.

        Raises:
            ConfigurationError: If ``config`` has no revocation URL.
            RevocationError: If the revocation URL is invalid, the request cannot be sent,
                the request fails to reach the endpoint, or its response body is not a valid JSON object.
                The caught error is not attached as its cause or context.
        """
        if config.revocation_url is None:
            msg = "the provider configuration carries no revocation endpoint"
            raise ConfigurationError(msg)
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    config.revocation_url,
                    headers={"Authorization": f"Bearer {token}"},
                )
            # NOTE: httpx.InvalidURL is not an httpx.HTTPError, so it needs its own clause.
            except httpx.InvalidURL:
                failure_message, kind = "Failed to revoke Slack token: invalid URL", FailureKind.REFUSED
            except httpx.RequestError as exc:
                transport = http_failure(exc)
                failure_message, kind = f"Failed to revoke Slack token: {transport.description}", transport.kind
            except Exception:
                # Any other send failure can repeat the token's header, like the encoding error for a non-ASCII token.
                failure_message, kind = "Failed to revoke Slack token: request failed", FailureKind.UNEXPECTED
            else:
                if not response.is_success:
                    return False
                try:
                    data = decode_json_body(response)
                except ValueError:
                    failure_message, kind = "Failed to parse Slack revocation response", FailureKind.REFUSED
                else:
                    if not isinstance(data, dict):
                        msg = "Slack revocation response was not a JSON object"
                        raise RevocationError(msg, kind=FailureKind.REFUSED)
                    return data.get("ok") is True
        # NOTE: The caught errors hold the token-bearing request or the response, so this error must not reference them.
        # This raise stays outside the except blocks, where Python would set __context__ to the caught error.
        raise RevocationError(failure_message, kind=kind)


def preset(
    client_id: str,
    client_secret: str,
    *,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
    user_scopes: list[str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Slack OAuth provider configuration for installing an app in a workspace.

    Signing a person in is :func:`sign_in_preset` instead. Slack says each set of scopes must be
    requested in its own OAuth flow, and this flow's token endpoint returns no ID token, so the
    ``openid`` scope is refused here in either scope parameter.

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

    Args:
        client_id: The OAuth client identifier.
        client_secret: The OAuth client secret.
        scopes: The bot scopes to request.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters.
        user_scopes: The user scopes to request via Slack's ``user_scope``
            parameter, if any.

    Returns:
        The provider configuration paired with its revocation handler.

    Raises:
        ValueError: If both ``scopes`` and ``user_scopes`` are empty, if any scope parameter asks for
            the ``openid`` scope, or if ``extra_params`` sets ``scope``.
    """
    if not scopes and not user_scopes:
        msg = "Slack OAuth requires at least one scope in scopes or user_scopes"
        raise ConfigurationError(msg)

    if not scopes:
        msg = (
            "Slack returns no token for the app itself when a flow asks for user scopes alone, and a "
            "token response carrying no access token is refused, so this flow needs at least one bot "
            "scope. Use sign_in_preset to sign a person in."
        )
        raise ConfigurationError(msg)

    scope_separator = Provider.SLACK.scope_separator

    merged_extra = _extra_params_without_scope(extra_params)
    if user_scopes:
        merged_extra["user_scope"] = scope_separator.join(user_scopes)

    requested = scope_words([*scopes, merged_extra.get("user_scope", "")], scope_separator)
    if _SLACK_SIGN_IN_SCOPE in requested:
        msg = (
            "Slack serves Sign in with Slack from its own endpoints and returns no ID token from this "
            "flow, so the openid scope cannot be requested here. Use sign_in_preset for Sign in with Slack."
        )
        raise ConfigurationError(msg)

    required_scope_families: list[list[str]] = []
    if scopes:
        required_scope_families.append(list(scopes))
    if user_scopes:
        required_scope_families.append(list(user_scopes))

    declared = replace(_INSTALL_PRESET, required_scope_families=required_scope_families)
    config = declared.config(
        client_id, client_secret, scopes=scopes, redirect_uri=redirect_uri, extra_params=merged_extra
    )
    return config, SlackRevocationHandler()


def sign_in_preset(
    client_id: str,
    client_secret: str,
    *,
    scopes: list[str] | None = None,
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Slack OAuth provider configuration for Sign in with Slack.

    Installing an app in a workspace is :func:`preset` instead. Slack serves this flow from its
    OpenID endpoints, which are the only Slack endpoints that return an ID token, so this is the
    only Slack flow whose response can carry the nonce the request sent.

    ``openid`` is requested whether or not ``scopes`` asks for it, because Slack returns no ID
    token without it, and it is the one scope this flow cannot do without. A workspace scope is
    refused here, because Slack says each set of scopes must be requested in its own OAuth flow.
    The configuration names the issuer Slack states in its OpenID discovery document.

    Args:
        client_id: The OAuth client identifier.
        client_secret: The OAuth client secret.
        scopes: The further scopes to request beside ``openid``, which are ``email`` and ``profile``.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters.

    Returns:
        The provider configuration paired with its revocation handler.

    Raises:
        ValueError: If ``scopes`` asks for a scope outside this flow, if ``extra_params`` sets
            ``scope``, which would replace the requested scopes, or if it sets ``user_scope``,
            which this flow does not send.
    """
    merged_extra = _extra_params_without_scope(extra_params)
    if "user_scope" in merged_extra:
        msg = (
            "Sign in with Slack sends no user_scope parameter, so extra_params cannot set one. "
            "Use preset to install a workspace app."
        )
        raise ConfigurationError(msg)

    requested = list(scopes or [])
    outside_this_flow = sorted(scope_words(requested, Provider.SLACK.scope_separator) - _SLACK_SIGN_IN_SCOPES)
    if outside_this_flow:
        msg = (
            f"Slack serves Sign in with Slack from its own endpoints, which grant {sorted(_SLACK_SIGN_IN_SCOPES)} "
            f"alone, so {outside_this_flow} cannot be requested here. Use preset to install a workspace app."
        )
        raise ConfigurationError(msg)
    if _SLACK_SIGN_IN_SCOPE not in scope_words(requested, Provider.SLACK.scope_separator):
        requested.insert(0, _SLACK_SIGN_IN_SCOPE)

    config = _SIGN_IN_PRESET.config(
        client_id, client_secret, scopes=requested, redirect_uri=redirect_uri, extra_params=merged_extra
    )
    return config, SlackRevocationHandler()
