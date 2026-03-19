# any-auth

Stateless OAuth 2.0 protocol library with PKCE, token refresh, and provider-specific revocation.

## What is any-auth?

Provider-specific OAuth knowledge — endpoints, auth methods, PKCE quirks, error classification, and revocation — encoded as a library so your application doesn't have to maintain it.

| What                 | Why                                                                                                                                       |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| Provider presets     | Endpoints, auth methods, PKCE toggles, scope separators, and revocation for multiple providers out of the box.                            |
| Error classification | Distinguishes permanent failures (revoked token, invalid client) from transient ones so callers know whether to retry or re-authenticate. |
| Revocation handlers  | Providers all revoke tokens differently (POST, DELETE, GET, Basic auth, query params) — presets include the right handler for each.       |
| Auth method handling | `client_secret_post` vs `client_secret_basic` — picked from your config and handled by authlib under the hood.                            |
| PKCE (S256)          | Generated automatically when the provider supports it, no setup needed.                                                                   |

any-auth is stateless. It doesn't store tokens, manage sessions, or hold database connections — you bring your own storage, any-auth handles the protocol.

## Installation

```bash
# via uv
uv add any-auth

# via pip
pip install any-auth
```

Requires Python 3.11+.

## Usage

### With a provider preset

Presets bundle the endpoints, auth method, PKCE config, and revocation handler for a given provider into a single call.

```python
from any_auth.providers import google

config, revocation_handler = google.preset(
    client_id="your-client-id",
    client_secret="your-client-secret",  # pragma: allowlist secret
    scopes=["openid", "email", "profile"],
)
```

If you use [any-tool](https://github.com/mozilla-ai/any-tool), scopes come from capability groups instead of being hardcoded:

```python
from any_tool.providers.google.gmail.scopes import CAPABILITY_GROUP as GMAIL

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
from any_auth import ProviderConfig

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
from any_auth import OAuthClient

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

### Token refresh

Refreshing can fail permanently (the user revoked access, the client was deregistered) or transiently (network blip, rate limit). any-auth tells you which.

```python
from any_auth import PermanentOAuthError

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
from any_auth import StateStore, OAuthPendingState

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

## Provider presets

| Provider   | Preset                   | Revocation             |
|------------|--------------------------|------------------------|
| Google     | `google.preset(...)`     | POST with query param  |
| GitHub     | `github.preset(...)`     | DELETE with Basic auth |
| Slack      | `slack.preset(...)`      | GET with query param   |
| Microsoft  | `microsoft.preset(...)`  | —                      |
| Atlassian  | `atlassian.preset(...)`  | RFC 7009 POST          |
| Linear     | `linear.preset(...)`     | RFC 7009 POST          |
| Notion     | `notion.preset(...)`     | —                      |
| Salesforce | `salesforce.preset(...)` | RFC 7009 POST          |
| Typeform   | `typeform.preset(...)`   | —                      |

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
