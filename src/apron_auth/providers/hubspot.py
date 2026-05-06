"""HubSpot OAuth provider preset, identity handler, and revocation handler.

``disconnect_fully_revokes=False``: per HubSpot's own documentation,
deleting a refresh token invalidates that token (and any access
tokens issued from it) but does not uninstall the app or remove the
portal-level OAuth grant. A subsequent re-auth reuses the existing
grant without a fresh consent screen, so consumers must surface a
deep link to HubSpot's connected-apps settings for manual removal.

Identity is fetched via HubSpot's access-token introspection endpoint,
which carries the bearer token in the URL path rather than an
``Authorization`` header. The handler therefore takes care never to
include the request URL — or any string derived from a captured httpx
exception, since those typically embed the URL — in the messages of
:class:`IdentityFetchError`, and explicitly breaks the exception
cause chain (``raise ... from None``) on the request and parse paths
so that default traceback rendering and ``logging.exception()`` —
which walk ``__cause__`` and ``__context__`` — cannot surface the
URL-embedded token through the wrapped httpx exception. The identity
returned is best-effort and mixes user and portal/account fields:
``user`` / ``user_id`` identify the HubSpot user, while ``hub_id`` /
``hub_domain`` identify the portal (and ``hub_domain`` is exposed via
:attr:`IdentityProfile.username`).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError, RevocationError
from apron_auth.models import IdentityProfile, ProviderConfig, ScopeMetadata
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


logger = logging.getLogger(__name__)


BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="oauth",
        label="App Authorization",
        description="Authorize this app to act on your behalf in HubSpot",
        access_type="read",
        required=True,
    ),
]

BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]

_HUBSPOT_IDENTITY_HOST_SUFFIXES = ("api.hubapi.com", "app.hubspot.com")
_HUBSPOT_TOKEN_INTROSPECT_URL_PREFIX = "https://api.hubapi.com/oauth/v1/access-tokens/"


class HubSpotIdentityHandler:
    """Fetch identity fields from HubSpot's access-token introspection endpoint.

    HubSpot exposes ``GET /oauth/v1/access-tokens/{access_token}`` as
    the OAuth-token introspection endpoint. The bearer token travels
    in the URL path, not an ``Authorization`` header, which makes the
    request URL itself a secret. To avoid leaking that secret on
    failure, this handler never includes the request URL — or any
    captured ``httpx`` exception's string form, which typically embeds
    the URL — in :class:`IdentityFetchError` messages.

    The introspection response mixes user and portal/account identity:

    - ``user_id`` (number) → :attr:`IdentityProfile.subject` (cast to ``str``)
    - ``user`` (the HubSpot user's email) → :attr:`IdentityProfile.email`
    - ``hub_domain`` (the portal account domain) → :attr:`IdentityProfile.username`

    HubSpot does not return an ``email_verified`` claim or a display
    name, so :attr:`IdentityProfile.email_verified` and
    :attr:`IdentityProfile.name` are always ``None``. The full
    response — including ``hub_id``, ``hub_domain``, ``app_id``,
    ``scopes``, ``token_type``, and ``expires_in`` — is preserved on
    :attr:`IdentityProfile.raw` for callers that need the portal-level
    fields.
    """

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a HubSpot access token."""
        del config
        introspect_url = f"{_HUBSPOT_TOKEN_INTROSPECT_URL_PREFIX}{quote(access_token, safe='')}"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(introspect_url)
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # Drop the cause chain: ``raise_for_status`` builds a message that
            # embeds the request URL (which contains the access token), so any
            # caller printing the traceback would leak the token.
            status_code = exc.response.status_code
            raise IdentityFetchError(
                f"Failed to fetch HubSpot identity: HTTP {status_code}",
            ) from None
        except httpx.RequestError as exc:
            # Drop the cause chain: httpx transport errors commonly include the
            # request URL — and therefore the access token — in their str().
            error_name = type(exc).__name__
            raise IdentityFetchError(
                f"Failed to fetch HubSpot identity: {error_name}",
            ) from None

        try:
            payload = response.json()
        except ValueError:
            # Drop the cause chain: JSON decoder errors can include surrounding
            # bytes, which for a 2xx body are unlikely to leak the token but
            # are stripped here for symmetry with the request-error paths.
            raise IdentityFetchError("Failed to parse HubSpot identity response") from None

        user_id = payload.get("user_id")
        return IdentityProfile(
            subject=str(user_id) if user_id is not None else None,
            email=payload.get("user"),
            email_verified=None,
            name=None,
            username=payload.get("hub_domain"),
            avatar_url=None,
            raw=payload,
        )


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
        self._client = client

    async def _send(self, client: httpx.AsyncClient, url: str) -> bool:
        try:
            response = await client.delete(url)
        except httpx.RequestError as exc:
            raise RevocationError(str(exc)) from exc
        if response.status_code in (204, 404):
            return True
        logger.warning(
            "HubSpot revocation returned unexpected status %s",
            response.status_code,
        )
        return False

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a HubSpot refresh token.

        The ``token`` argument must be the refresh token issued by
        HubSpot. The final request URL is built by appending the
        URL-encoded refresh token to ``config.revocation_url``.
        Returns True on 204 (revoked) or 404 (already gone —
        idempotent). Returns False for any other status code.
        Raises :class:`RevocationError` on network failure.
        """
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
        encoded = quote(token, safe="")
        url = f"{config.revocation_url.rstrip('/')}/{encoded}"
        if self._client is not None:
            return await self._send(self._client, url)
        async with httpx.AsyncClient() as client:
            return await self._send(client, url)


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the HubSpot identity handler when config matches HubSpot hosts.

    HubSpot's ``authorize_url`` and ``token_url`` use distinct hosts
    (``app.hubspot.com`` and ``api.hubapi.com`` respectively), so both
    must match the HubSpot suffix list. Requiring both — rather than
    either — prevents a misconfigured ``ProviderConfig`` with one
    HubSpot-shaped URL and one attacker-controlled URL from inferring
    this handler and routing the bearer token to a non-HubSpot host.
    """
    if oauth_hosts_match(config, _HUBSPOT_IDENTITY_HOST_SUFFIXES):
        return HubSpotIdentityHandler()
    return None


IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="hubspot",
    resolver=maybe_identity_handler,
)


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
    """
    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://app.hubspot.com/oauth/authorize",
        token_url="https://api.hubapi.com/oauth/v1/token",
        revocation_url="https://api.hubapi.com/oauth/v1/refresh-tokens",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        token_endpoint_auth_method="client_secret_post",
        extra_params=extra_params or {},
        scope_metadata=BASE_SCOPE_METADATA,
    )
    return config, HubSpotRevocationHandler()
