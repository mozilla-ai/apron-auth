"""Microsoft OAuth provider preset."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr

from apron_auth.models import ProviderConfig

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler


BASE_SCOPES = [
    "offline_access",
    "openid",
    "User.Read",
]


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
    )
    return config, None
