"""Typeform OAuth provider preset.

``disconnect_fully_revokes=False``: Typeform does not expose an OAuth
revocation endpoint at all (no revocation handler is returned), so
apron-auth has no way to remove the portal-level grant.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr

from apron_auth.models import ProviderConfig

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler | None]:
    """Create a Typeform OAuth provider configuration.

    Typeform does not support PKCE and does not provide a revocation
    endpoint.
    """
    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://api.typeform.com/oauth/authorize",
        token_url="https://api.typeform.com/oauth/token",
        redirect_uri=redirect_uri,
        scopes=scopes,
        use_pkce=False,
        extra_params=extra_params or {},
    )
    return config, None
