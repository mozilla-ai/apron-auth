"""Linear OAuth provider preset and identity handler.

``disconnect_fully_revokes`` defaults to ``False``: Linear's RFC 7009
``POST /oauth/revoke`` invalidates the supplied token but its effect
on the workspace-level OAuth grant has not been verified end-to-end.
Tracking issue: #34.

The identity handler issues a GraphQL ``viewer`` query against
``https://api.linear.app/graphql``. Linear returns GraphQL errors as
HTTP 200 responses with a non-empty ``errors`` array, so the handler
inspects the response body even on success status codes and raises
``IdentityFetchError`` when errors are present.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig
from apron_auth.protocols import StandardRevocationHandler
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


_LINEAR_GRAPHQL_URL = "https://api.linear.app/graphql"
_LINEAR_VIEWER_QUERY = "query { viewer { id name displayName email avatarUrl } }"
_LINEAR_IDENTITY_HOST_SUFFIXES = ("linear.app",)


class LinearIdentityHandler:
    """Fetch identity fields via Linear's GraphQL ``viewer`` query."""

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Linear access token."""
        del config
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    _LINEAR_GRAPHQL_URL,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    },
                    json={"query": _LINEAR_VIEWER_QUERY},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Linear identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Linear identity response: {exc}") from exc

        if not isinstance(payload, dict):
            raise IdentityFetchError("Linear GraphQL response was not a JSON object")

        errors = payload.get("errors")
        if errors:
            raise IdentityFetchError(f"Linear GraphQL returned errors: {errors}")

        data = payload.get("data")
        viewer = data.get("viewer") if isinstance(data, dict) else None
        if not isinstance(viewer, dict):
            raise IdentityFetchError("Linear GraphQL response missing data.viewer")

        return IdentityProfile(
            subject=viewer.get("id"),
            email=viewer.get("email"),
            email_verified=None,
            name=viewer.get("name"),
            username=viewer.get("displayName"),
            avatar_url=viewer.get("avatarUrl"),
            raw=viewer,
        )


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Linear identity handler when config matches Linear hosts."""
    if oauth_hosts_match(config, _LINEAR_IDENTITY_HOST_SUFFIXES):
        return LinearIdentityHandler()
    return None


IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="linear",
    resolver=maybe_identity_handler,
)


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Linear OAuth provider configuration."""
    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://linear.app/oauth/authorize",
        token_url="https://api.linear.app/oauth/token",
        revocation_url="https://api.linear.app/oauth/revoke",
        redirect_uri=redirect_uri,
        scopes=scopes,
        scope_separator=",",
        extra_params=extra_params or {},
    )
    return config, StandardRevocationHandler()
