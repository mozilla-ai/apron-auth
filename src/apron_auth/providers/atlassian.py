"""Atlassian OAuth provider preset and identity handler.

``disconnect_fully_revokes=False``: Atlassian does not document an
OAuth revoke endpoint that removes the user's portal-level grant.
Token revocation alone (where supported) does not clear the entry
under ``id.atlassian.com/manage-profile/apps``, so consumers must
surface a deep link to that page for manual removal.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityMaterial, IdentityProfile, ProviderConfig, ScopeMetadata, TenancyContext
from apron_auth.protocols import StandardRevocationHandler
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


logger = logging.getLogger(__name__)

_ATLASSIAN_ACCESSIBLE_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"
_ATLASSIAN_IDENTITY_HOST_SUFFIXES = ("auth.atlassian.com",)
_ATLASSIAN_USERINFO_URL = "https://api.atlassian.com/me"


def _build_tenancies(resources: Any) -> tuple[TenancyContext, ...]:
    """Build a tenancies tuple from the accessible-resources response.

    Skips any element that is not a dict or that lacks an ``id`` (the
    response field name; conceptually the Atlassian site ``cloudId``),
    which is the canonical key for an Atlassian site — ``name`` and
    ``url`` are decorative. ``name`` and ``domain`` may independently
    be ``None`` per the :class:`TenancyContext` contract — emit the
    entry anyway so callers retain the anchor identifier.

    Args:
        resources: The parsed accessible-resources response.

    Returns:
        One tenancy per resource carrying an ``id``, in response order; an
        empty tuple when ``resources`` is not a list.
    """
    if not isinstance(resources, list):
        return ()
    contexts: list[TenancyContext] = []
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        cloud_id = resource.get("id")
        if not cloud_id:
            continue
        # ``scopes`` and ``avatarUrl`` are provider-specific extras
        # with no normalized slot, so forward them via ``raw``.
        extras: dict[str, Any] = {}
        for key in ("scopes", "avatarUrl"):
            value = resource.get(key)
            if value is not None:
                extras[key] = value
        contexts.append(
            TenancyContext(
                id=str(cloud_id),
                name=_optional_str(resource.get("name")),
                domain=_optional_str(resource.get("url")),
                raw=extras,
            )
        )
    return tuple(contexts)


def _optional_str(value: Any) -> str | None:
    """Return ``value`` when it is a non-empty string, else ``None``."""
    return value if isinstance(value, str) and value else None


class AtlassianIdentityHandler:
    """Fetch identity fields from Atlassian's accessible-resources and User Identity APIs.

    Atlassian OAuth 2.0 (3LO) tokens can grant access to several Cloud
    sites (Jira, Jira Service Management, Confluence) under the same
    grant. ``/oauth/token/accessible-resources`` lists those sites and
    needs no scope beyond what any 3LO grant already carries, so it is
    the load-bearing call: one :class:`TenancyContext` is emitted per
    returned resource — making Atlassian the canonical multi-tenant case
    for the ``tenancies`` tuple shape — and a failure there fails the
    whole fetch.

    ``GET /me`` enriches the profile with the person-level fields
    (``subject``, ``email``, ``name``, ``username``, ``avatar_url``). It
    requires the ``read:me`` scope and that the "User Identity API" is
    enabled on the OAuth app in the Atlassian developer console — without
    that toggle, ``/me`` returns 401 even with a valid access token. Since
    every field it populates is optional, a refused or unparseable ``/me``
    response degrades to a tenancy-only profile with a warning rather
    than failing the fetch.

    The bearer token travels in the ``Authorization`` header on both
    calls (not the URL), so default httpx exception messages — which
    embed the request URL — do not embed the token; the standard
    ``raise ... from exc`` chain is therefore safe here.
    """

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using an Atlassian access token.

        Args:
            material: The token material to establish identity from.
            config: The provider configuration the tokens were issued under.

        Returns:
            The identity profile, with one tenancy per Atlassian Cloud site
            the token can access. Person-level fields are ``None`` and
            ``raw`` is empty when the User Identity API is unavailable.

        Raises:
            IdentityFetchError: If the accessible-resources request fails
                or its response cannot be parsed. The User Identity API
                request never raises; it degrades to a tenancy-only profile.
        """
        del config
        headers = {"Authorization": f"Bearer {material.access_token}"}
        async with httpx.AsyncClient() as client:
            tenancies = await self._fetch_tenancies(client, headers)
            payload = await self._fetch_profile(client, headers)

        return IdentityProfile(
            provider="atlassian",
            subject=payload.get("account_id"),
            email=payload.get("email"),
            email_verified=None,
            name=payload.get("name"),
            username=payload.get("nickname"),
            avatar_url=payload.get("picture"),
            tenancies=tenancies,
            raw=payload,
        )

    async def _fetch_tenancies(self, client: httpx.AsyncClient, headers: dict[str, str]) -> tuple[TenancyContext, ...]:
        """Resolve the sites the token can access into tenancies.

        Args:
            client: The HTTP client to issue the request with.
            headers: Request headers carrying the bearer token.

        Returns:
            One tenancy per accessible site, in response order.

        Raises:
            IdentityFetchError: If the request fails or its response cannot
                be parsed.
        """
        try:
            response = await client.get(_ATLASSIAN_ACCESSIBLE_RESOURCES_URL, headers=headers)
            response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Atlassian accessible resources: {exc}") from exc

        try:
            resources = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Atlassian accessible resources response: {exc}") from exc

        return _build_tenancies(resources)

    async def _fetch_profile(self, client: httpx.AsyncClient, headers: dict[str, str]) -> dict[str, Any]:
        """Fetch the person-level profile from the User Identity API.

        Every failure — a refused request, a transport error, or a body
        that is not a JSON object — is logged and yields an empty payload
        so the caller can still build a tenancy-only profile.

        Args:
            client: The HTTP client to issue the request with.
            headers: Request headers carrying the bearer token.

        Returns:
            The parsed ``/me`` payload, or an empty dict when it is
            unavailable.
        """
        try:
            response = await client.get(_ATLASSIAN_USERINFO_URL, headers=headers)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # The status is the whole diagnostic: 401 separates a missing
            # scope or disabled User Identity API from a transient failure.
            logger.warning(
                "atlassian user identity lookup was refused (status %s); "
                "emitting a tenancy-only profile without person-level fields",
                exc.response.status_code,
            )
            return {}
        except httpx.RequestError as exc:
            logger.warning(
                "atlassian user identity lookup failed (%s); "
                "emitting a tenancy-only profile without person-level fields",
                type(exc).__name__,
            )
            return {}

        try:
            payload = response.json()
        except ValueError:
            logger.warning(
                "atlassian user identity lookup could not parse the response; "
                "emitting a tenancy-only profile without person-level fields"
            )
            return {}

        if not isinstance(payload, dict):
            logger.warning(
                "atlassian user identity lookup returned a body that is not a JSON object; "
                "emitting a tenancy-only profile without person-level fields"
            )
            return {}
        return payload


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Atlassian identity handler when config matches Atlassian hosts.

    Args:
        config: The provider configuration to match.

    Returns:
        An Atlassian identity handler when the config's OAuth hosts are
        Atlassian's, else ``None``.
    """
    if oauth_hosts_match(config, _ATLASSIAN_IDENTITY_HOST_SUFFIXES):
        return AtlassianIdentityHandler()
    return None


IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="atlassian",
    resolver=maybe_identity_handler,
)


BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="offline_access",
        label="Offline Access",
        description="Issue refresh tokens for continued access without re-authorization",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="read:me",
        label="User Profile",
        description="View your Atlassian account profile for account identification",
        access_type="read",
        required=True,
    ),
]

BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create an Atlassian OAuth provider configuration.

    Scopes from BASE_SCOPES are merged automatically.

    Args:
        client_id: The OAuth client identifier.
        client_secret: The OAuth client secret.
        scopes: Additional scopes to request; merged with the required
            base scopes.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters; merged over
            the ``audience`` and ``prompt=consent`` defaults.

    Returns:
        The provider configuration paired with its revocation handler.
    """
    defaults = {"audience": "api.atlassian.com", "prompt": "consent"}
    if extra_params:
        defaults.update(extra_params)

    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://auth.atlassian.com/authorize",
        token_url="https://auth.atlassian.com/oauth/token",
        revocation_url="https://auth.atlassian.com/oauth/revoke",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        extra_params=defaults,
        scope_metadata=BASE_SCOPE_METADATA,
    )
    return config, StandardRevocationHandler()
