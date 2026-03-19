"""Notion OAuth provider preset."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr

from any_auth.models import ProviderConfig

if TYPE_CHECKING:
    from any_auth.protocols import RevocationHandler


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler | None]:
    """Create a Notion OAuth provider configuration.

    Notion uses client_secret_basic auth and does not provide a
    revocation endpoint.
    """
    defaults = {"owner": "user"}
    if extra_params:
        defaults.update(extra_params)

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://api.notion.com/v1/oauth/authorize",
        token_url="https://api.notion.com/v1/oauth/token",
        redirect_uri=redirect_uri,
        scopes=scopes,
        token_endpoint_auth_method="client_secret_basic",
        extra_params=defaults,
    )
    return config, None
