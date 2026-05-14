"""Microsoft OAuth provider preset and identity handler.

``disconnect_fully_revokes=False``: Microsoft does not expose a token
revocation endpoint usable by the application's own OAuth scopes —
removing the user's grant requires the user (or a tenant admin) to
remove the application from
``account.live.com/consent/Manage`` or the equivalent enterprise
admin surface. Consumers must surface a deep link to that page.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig, ScopeMetadata, TenancyContext
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


logger = logging.getLogger(__name__)

# The well-known tenant GUID Microsoft uses for personal MSA accounts.
# Per Microsoft Identity Platform docs: a ``tid`` of this value means the
# user signed in with a Microsoft account (Outlook.com, Xbox, etc.) that
# has no organization tenant. Treat as ``tenancies=()`` rather than
# fabricating a "consumers" tenant entry.
_MICROSOFT_CONSUMERS_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"
_MICROSOFT_IDENTITY_HOST_SUFFIXES = ("login.microsoftonline.com",)
_MICROSOFT_USERINFO_URL = "https://graph.microsoft.com/oidc/userinfo"


def _decode_jwt_tid(token: str) -> str | None:
    """Best-effort extraction of the ``tid`` claim from an access token.

    Microsoft Identity Platform v2 access tokens are JWTs whose payload
    carries the ``tid`` (tenant id) claim. The token has already been
    issued by a trusted OAuth flow at this point, so this function
    intentionally does not verify the signature — it only base64url-
    decodes the payload segment to read claims.

    Returns ``None`` when the token is not a parseable JWT, when the
    payload is not a JSON object, or when ``tid`` is absent. Microsoft's
    own docs state clients should not parse access tokens; this is a
    pragmatic best-effort path that ``fetch_identity`` falls back from
    cleanly when it does not work, rather than the load-bearing
    contract.
    """
    parts = token.split(".")
    if len(parts) < 2:
        # Opaque (non-JWT) access token — common in some Microsoft
        # configurations. Quiet at debug; not actionable for operators.
        logger.debug("microsoft access token is not in JWT shape; skipping tid extraction")
        return None
    try:
        # ``urlsafe_b64decode`` requires the input length to be a
        # multiple of 4; JWT segments are unpadded so we re-pad before
        # decoding.
        payload_b64 = parts[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded)
        payload = json.loads(payload_bytes)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        # Surface a debug-level signal so operators can detect a future
        # token-format change rather than every Microsoft auth silently
        # degrading to ``tenancies=()``. Includes the exception class
        # but not the value (avoids embedding any token-derived bytes).
        logger.debug("microsoft access token tid extraction failed: %s", type(exc).__name__)
        return None
    if not isinstance(payload, dict):
        logger.debug("microsoft access token payload was not a JSON object")
        return None
    tid = payload.get("tid")
    if not isinstance(tid, str) or not tid:
        return None
    return tid


class MicrosoftIdentityHandler:
    """Fetch identity fields from Microsoft Graph's OIDC userinfo endpoint.

    Microsoft's OIDC ``/oidc/userinfo`` endpoint returns only ``sub``,
    ``name``, ``family_name``, ``given_name``, ``picture``, and ``email``
    — it does not expose tenant identity. To populate ``tenancies``
    without an extra HTTP call, this handler best-effort decodes the
    access token JWT to read the ``tid`` claim. Microsoft documents
    that clients should not parse access tokens; the parser falls back
    to ``tenancies=()`` cleanly when the token is opaque or unparseable
    so the contract stays honest. Tenant ``name`` and ``domain`` are
    only available via the ``/v1.0/organization`` Graph endpoint, which
    is intentionally not called here.
    """

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Microsoft access token."""
        del config
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    _MICROSOFT_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Microsoft identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Microsoft identity response: {exc}") from exc

        tenancies: tuple[TenancyContext, ...] = ()
        tid = _decode_jwt_tid(access_token)
        if tid is not None and tid != _MICROSOFT_CONSUMERS_TENANT:
            tenancies = (TenancyContext(id=tid),)

        return IdentityProfile(
            provider="microsoft",
            subject=payload.get("sub"),
            email=payload.get("email"),
            email_verified=None,
            name=payload.get("name"),
            avatar_url=payload.get("picture"),
            tenancies=tenancies,
            raw=payload,
        )


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Microsoft identity handler when config matches Microsoft hosts."""
    if oauth_hosts_match(config, _MICROSOFT_IDENTITY_HOST_SUFFIXES):
        return MicrosoftIdentityHandler()
    return None


IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="microsoft",
    resolver=maybe_identity_handler,
)


BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="offline_access",
        label="Offline Access",
        description="Maintain access to data you have given it access to",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="openid",
        label="OpenID",
        description="Sign you in",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="User.Read",
        label="User Profile",
        description="Sign you in and read your profile",
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
) -> tuple[ProviderConfig, RevocationHandler | None]:
    """Create a Microsoft OAuth provider configuration.

    Microsoft does not provide a token revocation endpoint. Scopes from
    BASE_SCOPES are merged automatically.
    """
    defaults = {"prompt": "consent"}
    if extra_params:
        defaults.update(extra_params)

    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        extra_params=defaults,
        scope_metadata=BASE_SCOPE_METADATA,
    )
    return config, None
