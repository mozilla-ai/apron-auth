"""Linear OAuth provider preset."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr

from any_auth.models import ProviderConfig
from any_auth.protocols import StandardRevocationHandler

if TYPE_CHECKING:
    from any_auth.protocols import RevocationHandler


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
