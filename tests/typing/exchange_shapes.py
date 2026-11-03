"""Type-level assertions that each client accepts only its own exchange shape.

Nothing here runs. ``ty`` checks the file, and every ``ty: ignore`` marks a call that must stay a type
error. If a call below starts type-checking, its suppression becomes unused and the check fails, so these
are assertions rather than decoration.
"""

from __future__ import annotations

from pydantic import SecretStr

from apron_auth import (
    AuthorizationCallback,
    MemoryStateStore,
    OAuthClient,
    OAuthPendingState,
    ProviderConfig,
    StoredStateClient,
)

config = ProviderConfig(
    client_id="client",
    client_secret=SecretStr("secret"),  # pragma: allowlist secret
    authorize_url="https://provider.example.com/authorize",
    token_url="https://provider.example.com/token",
    redirect_uri="https://app.example.com/callback",
)
store = MemoryStateStore()
callback = AuthorizationCallback(code="code", state="state")
pending_state = OAuthPendingState(state="state", redirect_uri="https://app.example.com/callback", created_at=0.0)

caller_kept = OAuthClient(config)
stored = StoredStateClient(config, store)


async def each_client_accepts_its_own_shape() -> None:
    await caller_kept.exchange_code(callback, pending_state=pending_state)
    await stored.exchange_code(callback, browser_token="browser-token")


async def a_caller_kept_client_needs_the_pending_state() -> None:
    await caller_kept.exchange_code(callback)  # ty: ignore[missing-argument]


async def a_stored_state_client_takes_no_pending_state() -> None:
    await stored.exchange_code(
        callback,
        pending_state=pending_state,  # ty: ignore[unknown-argument]
        browser_token="browser-token",
    )


async def a_stored_state_client_needs_the_browser_token() -> None:
    await stored.exchange_code(callback)  # ty: ignore[missing-argument]


def a_caller_kept_client_takes_no_store() -> None:
    OAuthClient(config, state_store=store)  # ty: ignore[unknown-argument]


def a_collaborator_is_not_positional() -> None:
    OAuthClient(config, None)  # ty: ignore[too-many-positional-arguments]


def a_stored_state_client_needs_a_store() -> None:
    StoredStateClient(config)  # ty: ignore[missing-argument]
