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
print(identity.provider)        # "google", "github", etc.
print(identity.email)
print(identity.email_verified)
```

Built-in identity handlers are inferred from standard Google, GitHub,
HubSpot, Microsoft, Atlassian, Typeform, Salesforce, Notion, and Linear
endpoint hostnames, so they apply to both the bundled `preset(...)`
configs and any manually constructed `ProviderConfig` pointing at those
hosts. For other providers, pass a custom `identity_handler` to
`OAuthClient`.
OAuth protocol endpoints come from the provider config; identity API
endpoints are provider-specific internals handled by the identity
handler.

Typeform's `/me` response does not include a stable, opaque user
identifier, so `IdentityProfile.subject` is always `None` for that
provider. The available alternatives are `IdentityProfile.email`
(stable but PII) and `IdentityProfile.username` (the Typeform
alias, which is user-mutable); callers that need a non-PII stable
handle must derive one themselves, for example by hashing
`email`.

Notion's `/v1/users/me` returns a bot user object. For external (public
OAuth) integrations where `bot.owner.type == "user"`, `fetch_identity`
maps owner user fields into `IdentityProfile`. For internal
workspace-owned integrations where `bot.owner.type == "workspace"`,
Notion does not expose end-user email, so `IdentityProfile.email` is
`None` by design.

HubSpot's `fetch_identity` calls the access-token introspection
endpoint, which mixes user and portal/account identity in one
response. `IdentityProfile.subject` and `IdentityProfile.email` map to
the HubSpot user (`user_id` and `user`); the portal (`hub_id`,
`hub_domain`) populates `IdentityProfile.tenancies` (see "Tenancy"
below). The full response — including `app_id`, `scopes`, and
`expires_in` — is preserved on `IdentityProfile.raw`. HubSpot does not
return an `email_verified` claim, a display name, or a user handle,
so those fields are always `None`.

#### Tenancy

`IdentityProfile.tenancies` answers "what scope of resources does this
token operate within?" — the workspace, organization, tenant,
instance, portal, or site the OAuth access token is bound to. It is a
tuple of `TenancyContext` entries because Atlassian OAuth 2.0 (3LO)
tokens can grant access to several Cloud sites at once and a singleton
shape would force a lossy "pick one" decision in the handler.

| Provider count | Provider examples                                                 |
|----------------|-------------------------------------------------------------------|
| `()`           | GitHub OAuth Apps, Typeform, consumer Google, personal Microsoft |
| 1 entry        | Slack, Linear, Notion, Microsoft Entra, Salesforce, HubSpot, Google Workspace |
| Many entries   | Atlassian (Jira, Jira Service Management, Confluence)            |

Each `TenancyContext` exposes four normalized fields — `id`, `name`,
`domain`, `owns_email_domain` — plus a provider-specific `raw` payload
for fields that do not normalize cleanly. **Each normalized field may
independently be `None` (or `False` for `owns_email_domain`)** when
the provider's response does not assert that fact (for example,
Microsoft populates only `id` from the access-token `tid` claim;
Google Workspace populates `domain` from the `hd` claim and sets
`owns_email_domain=True`; HubSpot populates only `id` and `domain`
with `owns_email_domain=False`). Persist `id` as the canonical key —
provider-mutable handles like Linear's `urlKey` should not be treated
as permanent identifiers.

```python
identity = await client.fetch_identity(tokens.access_token)
for tenancy in identity.tenancies:
    print(tenancy.id, tenancy.name, tenancy.domain)
```

### Identifying users

Two facts on `IdentityProfile` are load-bearing for identifying users
safely: `provider` (which IdP issued the token) and `subject` (the
provider's stable, opaque user ID). The recommended primary key for a
consumer's user or identity table is the tuple `(provider, subject)`,
exposed via the `identity_key()` helper:

```python
identity = await client.fetch_identity(tokens.access_token)
key = identity.identity_key()  # ("google", "g-1") or None
if key is None:
    raise AuthError("Provider did not return a stable subject")
user = get_or_create_by_identity_key(key)
```

Email is a **display label**, not an identity. Use `verified_email()`
to surface the email at the call site only when the provider verified
it; otherwise treat the address as untrusted user input:

```python
display = identity.verified_email()  # None if not verified by provider
```

The verified-email assertion proves the user once controlled the inbox
at the time of verification. It does **not** prove ongoing control,
current employment, or that the email's domain belongs to any
organization the user is affiliated with. For those questions, see
[Domain-bound tenancy access](#domain-bound-tenancy-access).

#### Anti-pattern: keying users by email

```python
# DON'T
user = get_by_email(identity.email)  # cross-provider hijack vector
```

Treating email as a stable cross-provider identifier lets any
identity that presents a verified copy of an existing user's email —
on any supported provider — silently link into that user's account.
The verified flag from a provider like GitHub is sticky once acquired;
there is no out-of-band revocation when the user loses control of the
mailbox. Use `(provider, subject)` instead.

#### Suggested schema

A consumer keeping a separate identity table makes the recipe
mechanical and supports explicit, opt-in cross-provider account
linking:

```
oauth_identity
  provider               TEXT     -- PK part 1: "google", "github", ...
  subject                TEXT     -- PK part 2: provider's stable opaque user ID
  user_id                FK -> user.id
  email_at_link          TEXT     -- audit snapshot, not a lookup field
  email_verified_at_link BOOLEAN
  linked_at              TIMESTAMP
```

The `user` row keeps `email` as a display field only. Cross-provider
linking ("the same person, multiple providers") becomes an explicit
ceremony: an already-authenticated user adds a second identity by
completing OAuth on the second provider while logged in via the
first. Email lookups never silently merge accounts.

### Domain-bound tenancy access

When a consumer wants to grant access to an organization on the basis
of the user's email *domain* — for example, "anyone from acme.com
joins the Acme tenant automatically" — the verified-email signal
alone is not sufficient. A verified email proves inbox control; it
does not prove that the IdP issuing the token controls the email's
domain.

apron-auth surfaces the stronger fact via
`IdentityProfile.domain_owning_tenancy()`. This returns a
`TenancyContext` only when the provider asserts that the tenancy
controls the user's email domain (today: Google Workspace via the
`hd` claim; capability flag below). Returns `None` otherwise — gate
on the `None` case to refuse domain-based grants:

```python
def join_org(identity: IdentityProfile, claimed_domain: str) -> Membership:
    owner = identity.domain_owning_tenancy()
    if owner is None or owner.domain != claimed_domain:
        raise AuthError(f"No domain-owning assertion for {claimed_domain}")
    return grant_membership(identity.identity_key(), claimed_domain)
```

#### Refusing incapable providers at startup

`ProviderConfig.can_assert_domain_ownership` declares whether a
preset's tokens can *in principle* carry a domain-owning tenancy.
Consumers building a domain-gated tenancy flow can reject incapable
providers at startup, rather than discovering the gap at login time:

```python
config, _ = some_preset(client_id=..., client_secret=..., scopes=...)
if domain_gated_signin and not config.can_assert_domain_ownership:
    raise ConfigError(
        "This provider cannot assert domain ownership; do not "
        "wire it up for domain-gated tenancy."
    )
```

Per-provider capability:

| Provider     | `can_assert_domain_ownership` | Mechanism                                |
|--------------|-------------------------------|------------------------------------------|
| Google       | `True`                        | `hd` claim (Workspace accounts)          |
| Microsoft    | `False`                       | Verified-domain lookup planned; see issue tracker |
| GitHub       | `False`                       | No structural mechanism                  |
| Slack        | `False`                       | Workspace is not a domain authority      |
| Linear       | `False`                       | Workspace is not a domain authority      |
| Notion       | `False`                       | Workspace is not a domain authority      |
| HubSpot      | `False`                       | Portal is not a domain authority         |
| Atlassian    | `False`                       | Site is not a domain authority           |
| Salesforce   | `False`                       | Custom-domain investigation deferred     |
| Typeform     | `False`                       | No tenancy concept                       |

`False` is the security-preserving default. Future provider opt-ins
are strictly additive — a flag flipping from `False` to `True` only
loosens a gate, never tightens one. Pin a known-good provider list in
your config if you want changes to require an explicit code review.

#### Safe email allowlists

A common pattern is granting a role (admin, member, …) based on a
specific email address. The safe variant always pairs the email
check with a domain-ownership check, so a verified email from an
incapable provider cannot satisfy the allowlist alone:

```python
ADMIN_EMAILS = {"founder@example.com"}

def is_admin(identity: IdentityProfile) -> bool:
    return (
        identity.domain_owning_tenancy() is not None
        and identity.verified_email() in ADMIN_EMAILS
    )
```

Without the `domain_owning_tenancy()` check, any provider returning
`email_verified=True` for `founder@example.com` would grant admin —
including a personal GitHub account that happens to have
`founder@example.com` verified on it.

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
