"""OAuth 2.0 client for authorization code flows."""

from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from any_auth.errors import ConfigurationError
from any_auth.models import OAuthPendingState, TokenSet
from any_auth.pkce import generate_code_challenge, generate_code_verifier
from any_auth.scopes import join_scopes

if TYPE_CHECKING:
    from any_auth.models import ProviderConfig
    from any_auth.protocols import RevocationHandler, StateStore


class OAuthClient:
    """Stateless OAuth 2.0 client for authorization code flows."""

    def __init__(
        self,
        config: ProviderConfig,
        state_store: StateStore | None = None,
        revocation_handler: RevocationHandler | None = None,
    ) -> None:
        self._config = config
        self._state_store = state_store
        self._revocation_handler = revocation_handler

    async def get_authorization_url(
        self,
        redirect_uri: str | None = None,
    ) -> tuple[str, OAuthPendingState]:
        """Build an authorization URL with state and optional PKCE.

        If a StateStore is configured, the pending state is saved
        automatically before returning.
        """
        effective_redirect_uri = redirect_uri or self._config.redirect_uri
        if not effective_redirect_uri:
            msg = "redirect_uri must be provided either in the method call or in ProviderConfig"
            raise ConfigurationError(msg)

        state = secrets.token_urlsafe(32)
        code_verifier = None

        params: dict[str, str] = {
            "client_id": self._config.client_id,
            "response_type": "code",
            "redirect_uri": effective_redirect_uri,
            "state": state,
        }

        if self._config.scopes:
            params["scope"] = join_scopes(self._config.scopes, self._config.scope_separator)

        if self._config.use_pkce:
            code_verifier = generate_code_verifier()
            params["code_challenge"] = generate_code_challenge(code_verifier)
            params["code_challenge_method"] = "S256"

        params.update(self._config.extra_params)

        parsed = urlparse(self._config.authorize_url)
        existing_params = parse_qs(parsed.query)
        merged = {k: v[0] if len(v) == 1 else v for k, v in existing_params.items()}
        merged.update(params)
        url = urlunparse(parsed._replace(query=urlencode(merged, doseq=True)))

        pending_state = OAuthPendingState(
            state=state,
            redirect_uri=effective_redirect_uri,
            code_verifier=code_verifier,
            created_at=time.time(),
        )

        if self._state_store is not None:
            await self._state_store.save(pending_state)

        return url, pending_state
