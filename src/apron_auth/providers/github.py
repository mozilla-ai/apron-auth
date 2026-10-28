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
from collections.abc import Sequence
from dataclasses import replace
from typing import Any

import httpx

from apron_auth.models import IdentityMaterial, IdentityProfile, Provider, ProviderConfig, ScopeMetadata
from apron_auth.protocols import TransportFactory
from apron_auth.providers._identity_requests import fetch_identity_json
from apron_auth.providers._presets import Preset
from apron_auth.providers._revocation import HttpMethod, RevocationRequest, revocation_endpoint, send_revocation

logger = logging.getLogger(__name__)

# The scopes the preset always requests, with the labels a consent screen shows.
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

# The scope strings that the preset adds to the caller's scopes.
BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]

# What this provider's preset states, beside the values its caller passes.
# NOTE: The revocation endpoint names the client, so the preset states it per call.
_PRESET = Preset(
    provider=Provider.GITHUB,
    authorize_url="https://github.com/login/oauth/authorize",
    token_url="https://github.com/login/oauth/access_token",
    base_scopes=BASE_SCOPES,
    scope_metadata=BASE_SCOPE_METADATA,
)

# Maps a broad GitHub scope to the narrower scopes it implicitly grants.
# Only the immediate scopes each one implies are listed;
# ``resolve_implicit_scopes`` follows them transitively, so a chain such as
# ``admin:org`` -> ``write:org`` -> ``read:org`` is two edges, not three.
# Edges come from the documented scope table (each broad scope's indented
# sub-scopes) and the admin >= write >= read access ladders its descriptions
# establish. GitHub itself drops implicit scopes when normalizing a granted
# set ("Normalized scopes"). Source:
# https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
#
# Keep this conservative: an edge that is not a genuine documented superset
# makes consumers under-report genuinely missing scopes, so treat additions
# as security-relevant. Only scopes GitHub nests as documented sub-scopes are
# encoded. Prose that merely says one scope "can also do" another's job (e.g.
# ``repo`` grants hook and org access) is NOT an edge: the token's real scope
# list still omits those, so implying them would hide genuinely missing scopes.
IMPLICIT_SCOPES: dict[str, frozenset[str]] = {
    "admin:enterprise": frozenset({"manage_billing:enterprise", "manage_runners:enterprise", "read:enterprise"}),
    "admin:gpg_key": frozenset({"write:gpg_key"}),
    "admin:org": frozenset({"write:org"}),
    "admin:public_key": frozenset({"write:public_key"}),
    "admin:repo_hook": frozenset({"write:repo_hook"}),
    "project": frozenset({"read:project"}),
    "repo": frozenset({"public_repo", "repo:invite", "repo:status", "repo_deployment", "security_events"}),
    "user": frozenset({"read:user", "user:email", "user:follow"}),
    "write:gpg_key": frozenset({"read:gpg_key"}),
    "write:org": frozenset({"read:org"}),
    "write:public_key": frozenset({"read:public_key"}),
    "write:repo_hook": frozenset({"read:repo_hook"}),
}

# The headers every GitHub API request sends, which pin the API version.
_GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# The endpoint that lists the user's email addresses with their verified flags.
_GITHUB_EMAILS_URL = "https://api.github.com/user/emails"

# The endpoint that returns the signed-in user's profile.
_GITHUB_USER_URL = "https://api.github.com/user"

# The status GitHub answers when it validated the grant removal and refused it, or throttled it as spam.
_GITHUB_VALIDATION_FAILED = 422


def _derive_github_email(user_payload: dict[str, Any], emails_payload: Any) -> tuple[str | None, bool | None]:
    """Pick the best email and its verified flag from GitHub's responses.

    Prefers the primary verified address, then any verified address, from
    the emails endpoint; falls back to the profile ``email`` (reported
    unverified) when the emails list yields nothing.

    Args:
        user_payload: The parsed ``/user`` profile response.
        emails_payload: The parsed ``/user/emails`` response, if any.

    Returns:
        The ``(email, email_verified)`` pair, each ``None`` when no email
        is available.
    """
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

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a GitHub access token.

        Args:
            material: The token material to establish identity from.
            config: The provider configuration the tokens were issued under.

        Returns:
            The identity profile. GitHub OAuth App tokens carry no tenancy,
            so ``tenancies`` is empty.

        Raises:
            IdentityFetchError: If a profile or email request fails, or a
                response cannot be parsed.
                The failed request's error is not attached as its cause or context.
        """
        del config
        headers = {
            "Authorization": f"Bearer {material.access_token}",
            **_GITHUB_API_HEADERS,
        }
        async with httpx.AsyncClient() as client:
            user_payload = await fetch_identity_json(client.get(_GITHUB_USER_URL, headers=headers), "GitHub identity")
            emails_payload = await fetch_identity_json(
                client.get(_GITHUB_EMAILS_URL, headers=headers), "GitHub identity"
            )

        email, email_verified = _derive_github_email(user_payload, emails_payload)
        subject = user_payload.get("id")

        # GitHub OAuth Apps issue user-scoped tokens; org membership
        # (``/user/orgs``) is a permission, not a token-scoping context.
        # SAML SSO scoping is enforced at request time and surfaces only
        # as a 403 with no field on the token to inspect, so there is
        # no normalized tenancy to populate. GitHub Apps (a separate
        # auth model from OAuth Apps) ARE installation-scoped — if
        # apron-auth ever supports GitHub Apps as a distinct provider,
        # that installation should populate ``tenancies``.
        return IdentityProfile(
            provider=Provider.GITHUB,
            subject=str(subject) if subject is not None else None,
            email=email,
            email_verified=email_verified,
            name=user_payload.get("name") or user_payload.get("login"),
            username=user_payload.get("login"),
            avatar_url=user_payload.get("avatar_url"),
            tenancies=(),
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

    def __init__(self, *, transport_factory: TransportFactory | None = None) -> None:
        """Configure how revocation requests reach the network.

        Args:
            transport_factory: Controls the outbound connection for the revocation URL. The URL is
                server-supplied, so a caller handling untrusted input can pin DNS to validated
                addresses here to prevent SSRF via rebinding.
                NOTE: The transport it returns is closed when the request completes, so a factory
                must not return one it intends to reuse.
        """
        self._transport_factory = transport_factory

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke the GitHub OAuth grant at the configured revocation endpoint.

        Args:
            token: The access token whose grant is removed.
            config: The provider configuration supplying the revocation URL
                and client credentials.

        Returns:
            ``True`` when the grant is removed (or already absent), ``False``
            when GitHub reports a soft failure.

        Raises:
            ConfigurationError: If ``config`` declares no revocation endpoint, or declares one on a
                host it does not permit revocation at.
            RevocationError: If the endpoint URL is invalid, or the request cannot be sent or fails
                to arrive.
                The failed request's error is not attached as its cause or context.
        """
        request = RevocationRequest(
            url=revocation_endpoint(config),
            label="GitHub",
            method=HttpMethod.DELETE,
            auth=config.basic_auth(),
            headers=_GITHUB_API_HEADERS,
            json_body={"access_token": token},
        )
        response = await send_revocation(request, config, transport_factory=self._transport_factory)
        # 204: grant removed. 404: already gone, an idempotent re-disconnect.
        if response.status_code in (204, 404):
            return True
        # 422: validation failed or spam-throttled per GitHub's documentation. A soft failure, so a
        # caller can continue with local cleanup.
        if response.status_code == _GITHUB_VALIDATION_FAILED:
            logger.warning(
                "GitHub grant revocation returned 422 (validation failed "
                "or spam-throttled); the grant may still exist at GitHub"
            )
            return False
        logger.warning("GitHub grant revocation returned unexpected status %s", response.status_code)
        return False


def preset(
    client_id: str,
    client_secret: str,
    *,
    scopes: Sequence[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> ProviderConfig:
    """Create a GitHub OAuth provider configuration.

    Scopes from BASE_SCOPES are merged automatically — ``read:user`` and
    ``user:email`` are required for account identification on the
    consent screen.

    Args:
        client_id: The OAuth client identifier.
        client_secret: The OAuth client secret.
        scopes: Additional scopes to request; merged with the required
            base scopes.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters.

    Returns:
        The provider configuration. The client resolves this provider's revocation handler
        from it.
    """
    declared = replace(
        _PRESET,
        revocation_url=f"https://api.github.com/applications/{client_id}/grant",
        implicit_scopes=IMPLICIT_SCOPES,
    )
    config = declared.config(
        client_id, client_secret, scopes=scopes, redirect_uri=redirect_uri, extra_params=extra_params
    )
    return config
