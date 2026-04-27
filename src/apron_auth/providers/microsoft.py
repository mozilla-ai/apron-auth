"""Microsoft OAuth provider preset.

``disconnect_fully_revokes=False``: Microsoft does not expose a token
revocation endpoint usable by the application's own OAuth scopes —
removing the user's grant requires the user (or a tenant admin) to
remove the application from
``account.live.com/consent/Manage`` or the equivalent enterprise
admin surface. Consumers must surface a deep link to that page.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr

from apron_auth.models import ProviderConfig, ScopeMetadata

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler


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
