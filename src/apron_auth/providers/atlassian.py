"""Atlassian OAuth provider preset.

``disconnect_fully_revokes=False``: Atlassian does not document an
OAuth revoke endpoint that removes the user's portal-level grant.
Token revocation alone (where supported) does not clear the entry
under ``id.atlassian.com/manage-profile/apps``, so consumers must
surface a deep link to that page for manual removal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr

from apron_auth.models import ProviderConfig
from apron_auth.protocols import StandardRevocationHandler

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler


BASE_SCOPES = [
    "offline_access",
    "read:me",
]


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create an Atlassian OAuth provider configuration.

    Scopes from BASE_SCOPES are merged automatically.
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
    )
    return config, StandardRevocationHandler()
