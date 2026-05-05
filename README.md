# apron-auth

Stateless OAuth 2.0 protocol library with PKCE, token refresh, and provider-specific revocation.

## What is apron-auth?

Provider-specific OAuth knowledge — endpoints, auth methods, PKCE quirks, error classification, and revocation — encoded as a library so your application doesn't have to maintain it.

| What                 | Why                                                                                                                                       |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| Provider presets     | Endpoints, auth methods, PKCE toggles, scope separators, and revocation for multiple providers out of the box.                            |
| Error classification | Distinguishes permanent failures (revoked token, invalid client) from transient ones so callers know whether to retry or re-authenticate. |
| Revocation support   | Providers all revoke differently (POST, DELETE, GET, Basic auth, query params) — presets include the right handler when available.          |
| Auth method handling | `client_secret_post` vs `client_secret_basic` — picked from your config and handled by authlib under the hood.                            |
| PKCE (S256)          | Generated automatically when the provider supports it, no setup needed.                                                                   |

apron-auth is stateless. It doesn't store tokens, manage sessions, or hold database connections — you bring your own storage, apron-auth handles the protocol.

## Installation

```bash
# via uv
uv add apron-auth

# via pip
pip install apron-auth
```

Requires Python 3.11+.

## Usage

### With a provider preset

Presets bundle the endpoints, auth method, PKCE config, and revocation handler for a given provider into a single call.

```python
from apron_auth.providers import google

config, revocation_handler = google.preset(
    client_id="your-client-id",
    client_secret="your-client-secret",  # pragma: allowlist secret
    scopes=["openid", "email", "profile"],
)
```

If you use [apron-tools](https://github.com/mozilla-ai/apron-tools), scopes come from capability groups instead of being hardcoded:

```python
from apron_tools.providers.google.gmail.scopes import CAPABILITY_GROUP as GMAIL

config, revocation_handler = google.preset(
    client_id="your-client-id",
    client_secret="your-client-secret",  # pragma: allowlist secret
    scopes=GMAIL.scopes,
)
```

### Manual configuration

If your provider doesn't have a preset, configure it directly.

```python
from pydantic import SecretStr
from apron_auth import ProviderConfig

config = ProviderConfig(
    client_id="your-client-id",
    client_secret=SecretStr("your-client-secret"),  # pragma: allowlist secret
    authorize_url="https://provider.com/oauth/authorize",
    token_url="https://provider.com/oauth/token",
    scopes=["read", "write"],
)
```

### Authorization URL

Build the URL to redirect the user to. State and PKCE are included automatically.

```python
from apron_auth import OAuthClient

client = OAuthClient(config)
url, pending_state = await client.get_authorization_url(
    redirect_uri="https://yourapp.com/callback",
)
# Redirect the user to `url`.
# Hold onto `pending_state` — you'll need it for the callback.
```

### Code exchange

When the user comes back with an authorization code, exchange it for tokens.

```python
tokens = await client.exchange_code(
    code="authorization-code-from-callback",
    redirect_uri="https://yourapp.com/callback",
    code_verifier=pending_state.code_verifier,
)
print(tokens.access_token)
print(tokens.refresh_token)
```

### Identity fetch (optional)

If you need normalized identity fields for login or account-linking flows,
fetch them after token exchange:

```python
tokens = await client.exchange_code(
    code="authorization-code-from-callback",
    redirect_uri="https://yourapp.com/callback",
    code_verifier=pending_state.code_verifier,
)
identity = await client.fetch_identity(tokens.access_token)
print(identity.email)
print(identity.email_verified)
```

Built-in identity handlers are inferred from standard Google and GitHub
endpoint hostnames, so they apply to both the bundled `preset(...)` configs
and any manually constructed `ProviderConfig` pointing at those hosts. For
other providers, pass a custom `identity_handler` to `OAuthClient`. OAuth
protocol endpoints come from the provider config; identity API endpoints
are provider-specific internals handled by the identity handler.

### Token refresh

Refreshing can fail permanently (the user revoked access, the client was deregistered) or transiently (network blip, rate limit). apron-auth tells you which.

```python
from apron_auth import PermanentOAuthError

try:
    tokens = await client.refresh_token(tokens.refresh_token)
except PermanentOAuthError:
    # The token can't be recovered — delete it and re-authenticate the user.
    pass
```

By default, `invalid_grant`, `unauthorized_client`, and `invalid_client` are treated as permanent. If your provider uses non-standard error codes for the same thing, you can extend the set:

```python
client = OAuthClient(
    config,
    permanent_error_codes={"token_revoked", "account_suspended"},
)
```

These merge with the defaults — you can inspect them via `OAuthClient.DEFAULT_PERMANENT_ERROR_CODES`.

### Token revocation

```python
client = OAuthClient(config, revocation_handler=revocation_handler)
await client.revoke_token(tokens.access_token)
```

### State management

If you need to persist OAuth state across requests (e.g. between the redirect and the callback), implement the `StateStore` protocol.

```python
from apron_auth import StateStore, OAuthPendingState

class MyStateStore:
    async def save(self, state: OAuthPendingState) -> None:
        # Persist state, keyed by state.state.
        ...

    async def consume(self, state_key: str) -> OAuthPendingState | None:
        # Look up and invalidate in one step. Return None if it's missing or expired.
        ...

client = OAuthClient(config, state_store=MyStateStore())
url, pending_state = await client.get_authorization_url(
    redirect_uri="https://yourapp.com/callback",
)

# When the callback arrives, pass the state parameter and the code.
# The store is consumed automatically.
tokens = await client.exchange_code(code="...", state="state-from-callback")
```

#### Carrying context through the flow

If your application needs to carry context through the OAuth flow (e.g. which user or tenant initiated it), pass `metadata` when building the authorization URL. apron-auth carries it opaquely through the `StateStore` and surfaces it on `TokenSet.context` after auto-consume.

```python
url, pending_state = await client.get_authorization_url(
    redirect_uri="https://yourapp.com/callback",
    metadata={"user_id": "U123", "tenant_id": "T456"},
)

# On callback, context comes back on the TokenSet.
tokens = await client.exchange_code(code="...", state="state-from-callback")
print(tokens.context["user_id"])    # "U123"
print(tokens.context["tenant_id"])  # "T456"

# Provider response extras (e.g. Slack's team_id) are separate.
print(tokens.metadata)  # {"team_id": "T123", ...}
```

## Provider presets

| Provider   | Preset                   | Revocation             | `disconnect_fully_revokes` |
|------------|--------------------------|------------------------|----------------------------|
| Google     | `google.preset(...)`     | POST with query param  | `True`                     |
| GitHub     | `github.preset(...)`     | DELETE with Basic auth | `True`                     |
| Slack      | `slack.preset(...)`      | GET with query param   | `False`                    |
| Notion     | `notion.preset(...)`     | POST with Basic auth   | `False`                    |
| Microsoft  | `microsoft.preset(...)`  | —                      | `False`                    |
| Atlassian  | `atlassian.preset(...)`  | RFC 7009 POST          | `False`                    |
| Linear     | `linear.preset(...)`     | RFC 7009 POST          | `False`                    |
| Salesforce | `salesforce.preset(...)` | RFC 7009 POST          | `False`                    |
| Typeform   | `typeform.preset(...)`   | —                      | `False`                    |
| HubSpot    | `hubspot.preset(...)`    | DELETE refresh-token   | `False`                    |

## Scope reduction tiers

Some providers' revocation endpoints fully remove the user's portal-level OAuth grant; others only invalidate the current token while the grant lingers. apron-auth surfaces this difference as `ProviderConfig.disconnect_fully_revokes` so consumers can offer the right scope-reduction UX without rebuilding the per-provider truth table inline.

| Tier | Meaning                                                                                                             | When                                |
|------|---------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| 1    | Automatic scope reduction: revoke + re-auth presents a fresh consent screen, narrower scopes take effect.           | `disconnect_fully_revokes is True`  |
| 3    | Manual via provider settings: deep-link the user to the provider's app management page; revoke alone is not enough. | `disconnect_fully_revokes is False` |

```python
from apron_auth.providers import google, hubspot

google_config, _ = google.preset(...)
hubspot_config, _ = hubspot.preset(...)

if google_config.disconnect_fully_revokes:
    ...  # tier 1: trigger revoke + re-auth in-app
else:
    ...  # tier 3: open the provider's app-management page
```

The default for unconfigured `ProviderConfig` is `False` — under-claiming the capability harmlessly falls back to the manual deep-link path.

### Trello

Trello's API uses OAuth 1.0 exclusively — there is no OAuth 2.0 support yet. Atlassian has [announced plans](https://community.developer.atlassian.com/t/rfc-89-introducing-oauth2-to-trello/90359) to introduce OAuth 2.0 (3LO) for Trello, but no launch date has been committed.

Because apron-auth is an OAuth 2.0 library, Trello is not supported. If your application needs Trello, handle its OAuth 1.0 flow separately (e.g. with [authlib](https://docs.authlib.org/en/latest/client/oauth1.html)). [apron-tools](https://github.com/mozilla-ai/apron-tools) provides Trello tool definitions — you just need to bring your own token.

When Trello ships OAuth 2.0, a preset will be added here.

## Error hierarchy

All exceptions inherit from `OAuthError`.

| Exception             | When it's raised                                                                                                |
|-----------------------|-----------------------------------------------------------------------------------------------------------------|
| `TokenExchangeError`  | Code exchange failed at the token endpoint.                                                                     |
| `TokenRefreshError`   | Refresh failed, but it might work if you try again (transient).                                                 |
| `PermanentOAuthError` | The token is gone — `invalid_grant`, `unauthorized_client`, or `invalid_client`. Delete it and re-authenticate. |
| `RevocationError`     | The provider rejected the revocation request.                                                                   |
| `StateError`          | OAuth state was invalid, expired, or already used.                                                              |
| `ConfigurationError`  | Something's wrong with the provider config (e.g. missing `redirect_uri`).                                       |

## Development

Requires [uv](https://docs.astral.sh/uv/).

```bash
make setup    # Install uv, create venv, sync deps, install pre-commit hooks
make test     # Run unit tests
make lint     # Run pre-commit hooks (ruff, ty, detect-secrets)
```

Or using uv directly:

```bash
uv sync --group dev
uv run pytest tests
uv run pre-commit run --all-files
```

## License

[Apache-2.0](LICENSE)
