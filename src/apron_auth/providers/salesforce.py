"""Salesforce OAuth provider preset.

``disconnect_fully_revokes`` defaults to ``False``: Salesforce's
RFC 7009 ``/services/oauth2/revoke`` invalidates the supplied token
but its effect on the org-level Connected App authorization has not
been verified end-to-end. Tracking issue: #35.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr

from apron_auth.models import ProviderConfig, ScopeMetadata
from apron_auth.protocols import StandardRevocationHandler

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler


BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="refresh_token",
        label="Refresh Token",
        description="Issue a refresh token so access can be renewed without re-authorization",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="offline_access",
        label="Offline Access",
        description="Maintain access to your Salesforce data when you are not actively using the app",
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
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Salesforce OAuth provider configuration.

    Scopes from BASE_SCOPES are merged automatically — Salesforce
    requires both ``refresh_token`` and ``offline_access`` to issue
    a refresh token at the code-exchange step.
    """
    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://login.salesforce.com/services/oauth2/authorize",
        token_url="https://login.salesforce.com/services/oauth2/token",
        revocation_url="https://login.salesforce.com/services/oauth2/revoke",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        extra_params=extra_params or {},
        scope_metadata=BASE_SCOPE_METADATA,
    )
    return config, StandardRevocationHandler()
