"""HubSpot OAuth provider preset, identity handler, and revocation handler.

``disconnect_fully_revokes=False``: per HubSpot's own documentation,
deleting a refresh token invalidates that token (and any access
tokens issued from it) but does not uninstall the app or remove the
portal-level OAuth grant. A subsequent re-auth reuses the existing
grant without a fresh consent screen, so consumers must surface a
deep link to HubSpot's connected-apps settings for manual removal.

Identity is fetched via HubSpot's access-token introspection endpoint,
which carries the bearer token in the URL path rather than an
``Authorization`` header.
An :class:`IdentityFetchError` from the identity handler holds no request URL and no HTTP client text.
The failed request's error is not attached as its cause or context, so the request cannot be reached from it.

NOTE: An error reporter that captures frame local variables can still record the token.
The request URL is a local variable while the request runs, and no error handling can remove it.

The introspection response mixes user and portal/account fields:
``user`` / ``user_id`` identify the HubSpot user, while ``hub_id`` /
``hub_domain`` identify the portal. Portal identity now lands in
:attr:`IdentityProfile.tenancies` rather than being shoved into
:attr:`IdentityProfile.username` (the prior workaround), so the
``IdentityProfile.username`` slot is ``None`` for HubSpot — there is
no human handle in the introspection payload to put there.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from apron_auth._http_errors import http_failure
from apron_auth.errors import ConfigurationError, RevocationError
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

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler


logger = logging.getLogger(__name__)


# The scopes the preset always requests, with the labels a consent screen shows.
BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="oauth",
        label="App Authorization",
        description="Authorize this app to act on your behalf in HubSpot",
        access_type="read",
        required=True,
    ),
]

# The scope strings that the preset adds to the caller's scopes.
BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]

# What this provider's preset states, beside the values its caller passes.
_PRESET = Preset(
    provider=Provider.HUBSPOT,
    authorize_url="https://app.hubspot.com/oauth/authorize",
    token_url="https://api.hubapi.com/oauth/v1/token",
    revocation_url="https://api.hubapi.com/oauth/v1/refresh-tokens",
    base_scopes=BASE_SCOPES,
    scope_metadata=BASE_SCOPE_METADATA,
)

# The token introspection endpoint, which takes the access token as the last path segment.
_HUBSPOT_TOKEN_INTROSPECT_URL_PREFIX = "https://api.hubapi.com/oauth/v1/access-tokens/"


class HubSpotIdentityHandler:
    """Fetch identity fields from HubSpot's access-token introspection endpoint.

    HubSpot exposes ``GET /oauth/v1/access-tokens/{access_token}`` as
    the OAuth-token introspection endpoint. The bearer token travels
    in the URL path, not an ``Authorization`` header, which makes the
    request URL itself a secret.
    An :class:`IdentityFetchError` from this handler holds no request URL and no HTTP client text.
    The failed request's error is not attached as its cause or context.

    The introspection response mixes user and portal/account identity:

    - ``user_id`` (number) → :attr:`IdentityProfile.subject` (cast to ``str``)
    - ``user`` (the HubSpot user's email) → :attr:`IdentityProfile.email`
    - ``hub_id`` (number) → ``tenancies[0].id`` (cast to ``str``)
    - ``hub_domain`` (the portal account domain) → ``tenancies[0].domain``

    HubSpot does not return an ``email_verified`` claim, a display
    name, a portal display name, or a user handle on the introspection
    payload, so :attr:`IdentityProfile.email_verified`,
    :attr:`IdentityProfile.name`, :attr:`IdentityProfile.username`,
    and ``tenancies[0].name`` are always ``None``. The full response —
    including ``app_id``, ``scopes``, ``token_type``, and
    ``expires_in`` — is preserved on :attr:`IdentityProfile.raw` for
    callers that need the rest of the introspection fields.
    """

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a HubSpot access token.

        Args:
            material: The token material to establish identity from.
            config: The provider configuration the tokens were issued under.

        Returns:
            The identity profile, with the portal surfaced as a single
            tenancy when the introspection response names one.

        Raises:
            IdentityFetchError: If the introspection request fails or its
                response cannot be parsed. Messages never include the
                request URL, which embeds the token.
        """
        del config
        introspect_url = f"{_HUBSPOT_TOKEN_INTROSPECT_URL_PREFIX}{quote(material.access_token, safe='')}"
        payload = await self._introspect(introspect_url)

        user_id = payload.get("user_id")
        hub_id = payload.get("hub_id")
        tenancies: tuple[TenancyContext, ...] = ()
        if hub_id is not None:
            # ``hub_id`` is the canonical portal anchor — gate on it.
            # ``hub_domain`` is decorative; if it is unexpectedly absent
            # the tenancy is still emitted with ``domain=None`` so the
            # caller does not silently lose the portal binding. The
            # introspection endpoint is documented to return both
            # together, so a missing ``hub_domain`` is an unexpected
            # response shape rather than an intentional contract.
            # ``name`` is always ``None`` for HubSpot — the
            # introspection response carries no portal display name,
            # nor does any other public HubSpot endpoint.
            tenancies = (
                TenancyContext(
                    id=str(hub_id),
                    domain=payload.get("hub_domain"),
                ),
            )

        return IdentityProfile(
            provider=Provider.HUBSPOT,
            subject=str(user_id) if user_id is not None else None,
            email=payload.get("user"),
            email_verified=None,
            name=None,
            username=None,
            avatar_url=None,
            tenancies=tenancies,
            raw=payload,
        )

    async def _introspect(self, introspect_url: str) -> Any:
        """Request the introspection endpoint and return the decoded body.

        Args:
            introspect_url: The introspection URL, which carries the access token.

        Returns:
            The decoded JSON body.

        Raises:
            IdentityFetchError: If the request fails or its response cannot be parsed.
                The failed request's error is not attached as its cause or context.
        """
        async with httpx.AsyncClient() as client:
            return await fetch_identity_json(client.get(introspect_url), "HubSpot identity")


class HubSpotRevocationHandler:
    """HubSpot token revocation via DELETE on the refresh-token path.

    HubSpot revokes by refresh token, not access token. Callers must
    pass the refresh token as the ``token`` argument to :meth:`revoke`.

    Revoking invalidates only the specific refresh token (and any access
    tokens issued from it). It does not uninstall the app or remove the
    portal-level OAuth grant, so a subsequent reauthorization flow will
    reuse the existing grant without presenting a fresh consent screen.
    Full grant removal requires a manual action in the HubSpot portal.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        """Configure the handler.

        Args:
            client: An optional caller-owned client to send revocation
                requests through; a fresh client is used per request when
                omitted.
        """
        self._client = client

    async def _send(self, client: httpx.AsyncClient, url: str) -> bool:
        """Send the revocation request and return success status.

        Args:
            client: The HTTP client to send the request through.
            url: The refresh-token revocation URL to DELETE.

        Returns:
            ``True`` on 204 (revoked) or 404 (already gone — idempotent),
            ``False`` on any other status.

        Raises:
            RevocationError: If the request fails to reach the endpoint.
                The failed request's error is not attached as its cause or context.
        """
        try:
            response = await client.delete(url)
        except httpx.RequestError as exc:
            failure = http_failure(exc)
        else:
            if response.status_code in (204, 404):
                return True
            logger.warning(
                "HubSpot revocation returned unexpected status %s",
                response.status_code,
            )
            return False
        # NOTE: The caught error holds the request, which carries the token, so this error must not reference it.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise RevocationError(f"Failed to revoke HubSpot token: {failure.description}", kind=failure.kind)

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a HubSpot refresh token.

        The ``token`` argument must be the refresh token issued by
        HubSpot. The final request URL is built by appending the
        URL-encoded refresh token to ``config.revocation_url``.

        Args:
            token: The refresh token to revoke.
            config: The provider configuration supplying the revocation URL.

        Returns:
            ``True`` on 204 (revoked) or 404 (already gone — idempotent),
            ``False`` for any other status.

        Raises:
            ConfigurationError: If ``config`` has no revocation URL.
            RevocationError: If the request fails to reach the endpoint.
                The failed request's error is not attached as its cause or context.
        """
        if config.revocation_url is None:
            msg = "the provider configuration carries no revocation endpoint"
            raise ConfigurationError(msg)
        encoded = quote(token, safe="")
        url = f"{config.revocation_url.rstrip('/')}/{encoded}"
        if self._client is not None:
            return await self._send(self._client, url)
        async with httpx.AsyncClient() as client:
            return await self._send(client, url)


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a HubSpot OAuth provider configuration.

    HubSpot uses ``client_secret_post`` token-endpoint authentication
    and a non-standard revocation endpoint that takes the refresh
    token in the URL path. The returned :class:`HubSpotRevocationHandler`
    expects the refresh token (not the access token) as the ``token``
    argument to :meth:`~HubSpotRevocationHandler.revoke`. See the
    handler docstring for the consent-screen caveat on reauthorization.

    Scopes from BASE_SCOPES are merged automatically — HubSpot requires
    the ``oauth`` scope on every app authorization.

    Args:
        client_id: The OAuth client identifier.
        client_secret: The OAuth client secret.
        scopes: Additional scopes to request; merged with the required
            base scopes.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters.

    Returns:
        The provider configuration paired with its revocation handler.
    """
    config = _PRESET.config(
        client_id, client_secret, scopes=scopes, redirect_uri=redirect_uri, extra_params=extra_params
    )
    return config, HubSpotRevocationHandler()
