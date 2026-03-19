"""Atlassian OAuth provider preset."""

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
    """Create an Atlassian OAuth provider configuration."""
    defaults = {"audience": "api.atlassian.com", "prompt": "consent"}
    if extra_params:
        defaults.update(extra_params)

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://auth.atlassian.com/authorize",
        token_url="https://auth.atlassian.com/oauth/token",
        revocation_url="https://auth.atlassian.com/oauth/revoke",
        redirect_uri=redirect_uri,
        scopes=scopes,
        extra_params=defaults,
    )
    return config, StandardRevocationHandler()
