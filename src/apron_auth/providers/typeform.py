"""Typeform OAuth provider preset and identity handler.

``disconnect_fully_revokes=False``: Typeform does not expose an OAuth
revocation endpoint at all (no revocation handler is returned), so
apron-auth has no way to remove the portal-level grant.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from apron_auth.errors import FailureKind, IdentityFetchError, IdentityScopeNotGrantedError
from apron_auth.models import IdentityMaterial, IdentityProfile, Provider, ProviderConfig, TimeoutPolicy
from apron_auth.providers._identity_requests import fetch_identity_json, identity_client, identity_transport
from apron_auth.providers._presets import Preset
from apron_auth.scopes import parse_scope

if TYPE_CHECKING:
    from apron_auth.protocols import TransportFactory

# What this provider's preset states, beside the values its caller passes.
_PRESET = Preset(
    provider=Provider.TYPEFORM,
    authorize_url="https://api.typeform.com/oauth/authorize",
    token_url="https://api.typeform.com/oauth/token",
    use_pkce=False,
)

# The scope the userinfo endpoint requires.
_TYPEFORM_USERINFO_SCOPE = "accounts:read"

# The endpoint that returns the signed-in user's account.
_TYPEFORM_USERINFO_URL = "https://api.typeform.com/me"


class TypeformIdentityHandler:
    """Fetch identity fields from Typeform's ``/me`` endpoint.

    Requires the ``accounts:read`` OAuth scope. The Typeform response
    documents only ``alias``, ``email``, and ``language``, so
    ``IdentityProfile.subject`` is always ``None`` for this provider —
    Typeform does not expose a stable, opaque user identifier. The
    available alternatives are ``email`` (stable but PII) and
    ``username`` (the Typeform ``alias``, which is user-mutable);
    callers that need a non-PII stable handle must derive one
    themselves, for example by hashing ``email``.
    """

    def __init__(self, *, transport_factory: TransportFactory | None = None) -> None:
        """Configure how an identity request reaches the provider.

        Args:
            transport_factory: Controls the outbound connection for every request this handler
                sends, where a caller handling untrusted input can pin DNS to validated addresses.
        """
        self._transport_factory = transport_factory

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Typeform access token.

        Args:
            material: The token material to establish identity from.
            config: The provider configuration the tokens were issued under.

        Returns:
            The identity profile. ``subject`` is always ``None`` and
            ``tenancies`` is empty, per this provider's response shape.

        Raises:
            IdentityScopeNotGrantedError: If the token's granted scopes are
                known and do not include ``accounts:read``.
            IdentityFetchError: If the userinfo request fails or its
                response cannot be parsed. When the granted scopes are
                unknown, a missing ``accounts:read`` also surfaces here.
                The failed request's error is not attached as its cause or context.
                A refusal by the caller's transport factory is reported here too, and chains the factory's own error.
        """
        # NOTE: Typeform answers a missing scope and a bad token with the same 403, so only a known grant is checked.
        granted_scopes = parse_scope(material.scope or "", config.scope_separator)
        if granted_scopes:
            granted = config.resolve_implicit_scopes(set(granted_scopes))
            if _TYPEFORM_USERINFO_SCOPE not in granted:
                raise IdentityScopeNotGrantedError(f"Typeform identity requires the {_TYPEFORM_USERINFO_SCOPE} scope")

        transport = identity_transport(self._transport_factory, _TYPEFORM_USERINFO_URL, "Typeform identity")
        async with identity_client(config.timeouts, transport=transport) as client:
            payload = await fetch_identity_json(
                client.get(
                    _TYPEFORM_USERINFO_URL,
                    headers={"Authorization": f"Bearer {material.access_token.get_secret_value()}"},
                ),
                "Typeform identity",
                config.timeouts,
            )

        if not isinstance(payload, dict):
            msg = "Typeform identity response was not a JSON object"
            raise IdentityFetchError(msg, kind=FailureKind.REFUSED)

        # Typeform "workspaces" are intra-account containers, not
        # OAuth-scoping contexts. A token authenticates the user and
        # grants access — governed by ``workspaces:read`` /
        # ``workspaces:write`` scopes — across every workspace the
        # user can see, so there is no normalized tenancy to populate.
        return IdentityProfile(
            provider=Provider.TYPEFORM,
            subject=None,
            email=payload.get("email"),
            email_verified=None,
            name=None,
            username=payload.get("alias"),
            avatar_url=None,
            tenancies=(),
            raw=payload,
        )


def preset(
    client_id: str,
    client_secret: str,
    *,
    scopes: Sequence[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
    timeouts: TimeoutPolicy | None = None,
) -> ProviderConfig:
    """Create a Typeform OAuth provider configuration.

    Typeform does not support PKCE and does not provide a revocation
    endpoint.

    Args:
        client_id: The OAuth client identifier.
        client_secret: The OAuth client secret.
        scopes: The scopes to request.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters.
        timeouts: The limits on every request sent for this provider.
            Defaults to :class:`~apron_auth.models.TimeoutPolicy`'s own.

    Returns:
        The provider configuration. It declares no revocation endpoint, because Typeform
        exposes none.
    """
    return _PRESET.config(
        client_id, client_secret, scopes=scopes, redirect_uri=redirect_uri, extra_params=extra_params, timeouts=timeouts
    )
