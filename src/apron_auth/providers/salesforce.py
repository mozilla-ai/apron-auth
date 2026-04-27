"""Salesforce OAuth provider preset.

``disconnect_fully_revokes`` defaults to ``False``: Salesforce's
RFC 7009 ``/services/oauth2/revoke`` invalidates the supplied token
but its effect on the org-level Connected App authorization has not
been verified end-to-end. Tracking issue: #35.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr

from apron_auth.models import ProviderConfig
from apron_auth.protocols import StandardRevocationHandler

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Salesforce OAuth provider configuration."""
    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://login.salesforce.com/services/oauth2/authorize",
        token_url="https://login.salesforce.com/services/oauth2/token",
        revocation_url="https://login.salesforce.com/services/oauth2/revoke",
        redirect_uri=redirect_uri,
        scopes=scopes,
        extra_params=extra_params or {},
    )
    return config, StandardRevocationHandler()
