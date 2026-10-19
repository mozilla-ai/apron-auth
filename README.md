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

### Any OpenID Connect provider

A provider that implements OpenID Connect publishes its own endpoints, so there is
nothing to hardcode: discover them from the issuer and hand the result to the preset.
This covers Keycloak, Okta, Auth0, Entra ID, Authentik, Zitadel, Dex, and Ping without
a module per product.

```python
from apron_auth import OAuthClient
from apron_auth.providers import oidc

metadata = await oidc.discover("https://sso.example.com/realms/acme")

config, revocation_handler = oidc.preset(
    client_id="your-client-id",
    client_secret="your-client-secret",  # pragma: allowlist secret
    scopes=["email", "profile"],
    metadata=metadata,
    redirect_uri="https://yourapp.com/callback",
)

client = OAuthClient(
    config,
    identity_handler=oidc.identity_handler(metadata),
)
```

The issuer is a trust anchor, not just an address: `discover` refuses a configuration
document that names a different one (OpenID Connect Discovery 1.0, section 4.3), and the
discovered issuer carries onto the config. The authorization-response `iss` (RFC 9207) is
validated before a code is redeemed only when the provider sends `iss` or advertises
`authorization_response_iss_parameter_supported`. An ID token whose `iss` differs from the
configured issuer is refused at the code exchange, and its tokens are revoked.

Entra needs a tenant-specific issuer such as `https://login.microsoftonline.com/<tid>/v2.0`.
The `/common` and `/organizations` documents name a templated issuer, which fails the issuer
match by design.

Always pass the identity handler explicitly, as above. The config that `preset` returns sets `allow_identity_inference=False`, so `fetch_identity` raises `IdentityNotSupportedError` without a handler. Inference would otherwise give a config on an Entra or Google host that provider's handler, with `provider` set to `microsoft` or `google` instead of `oidc:<issuer>`, and a different `identity_key()` for every user.

Build the handler and the config from the same `metadata`. The handler is bound to that
metadata's issuer, and it raises `ConfigurationError` for a config that names another issuer,
before any request. This keeps one issuer's access token away from another issuer's userinfo
endpoint.

ID token signatures are checked against the issuer's published key set (`jwks_uri`, which discovery requires), with public-key algorithms only. A token that does not verify raises `TokenValidationError`, or `TokenExpiredError` once it has expired, and identity never falls back to userinfo for it. The claims are then validated: `iss`, `sub`, `aud`, `exp`, `iat`, `azp`, and `at_hash` (against the access token). The handler then refuses a userinfo response whose `sub` is missing or disagrees with the ID token's. Pass the handler only tokens from a token-endpoint response, never a stored or front-channel token: the handler itself checks no `nonce`, so a validly signed token replayed from elsewhere would pass. `exchange_code` checks the nonce, the audience, the expiry, and the issuer when one is configured, before it returns the tokens.

Userinfo is enrichment when an ID token validated: if the call fails (Entra and Keycloak
answer 401/403 when the access token's audience is a resource API), a WARNING is logged and
identity rests on the ID token. With no usable ID token it is the only source, so the failure
raises, as `IdentityScopeNotGrantedError` for a 403 `insufficient_scope` (RFC 6750).

`IdentityProfile.provider` is `oidc:<issuer>`, not a bare `oidc`. A `sub` is unique only
within an issuer, so two generic connections would otherwise collide on the
`(provider, subject)` pair that `identity_key()` recommends as a user-table primary key.

`IdentityProfile.email_verified` is `None` by default. On a self-run IdP the claim is
whatever its admin set (Keycloak, Authentik and Zitadel all let an admin mark any address
verified), so honoring it would change what `verified_email()` means for every other
provider. Pass `trust_email_verified=True` to `oidc.identity_handler` to report it, which
says "I trust this issuer's admin to verify addresses". A multi-tenant application where each
customer brings its own IdP must not enable it for a tenant-supplied issuer: one tenant could
mint `ceo@other-tenant.com` with `email_verified=true`. Key users on `identity_key()`, which
stays safe either way. (A per-connection `verified_domains` option is the fuller design,
tracked in #136.)

PKCE is always on, and a provider whose `code_challenge_methods_supported` omits `S256` is refused at `preset` time. PKCE binds an authorization code to the session that requested it only where the provider enforces it: when the field is absent (Entra omits it) `preset` still uses PKCE and logs a WARNING, because a provider that ignores the challenge leaves the code unbound. When the request asks for `openid`, as the preset's scopes do unless `extra_params` replaces the scope, `get_authorization_url` also sends a `nonce`, and `exchange_code` refuses an ID token that does not carry it. A malformed `code_challenge_methods_supported` or `token_endpoint_auth_methods_supported` is a discovery error rather than "not advertised".

`discover` requires an absolute `https` URL for the issuer, the document URL, the signing key set, and every endpoint the document names (no fragment; the issuer also has no query or userinfo, per Discovery 1.0 section 4.1; a bad value raises `OidcDiscoveryError` naming the field), because the client secret and every token travel over them and the signing key set authenticates every ID token: over `http`, an on-path attacker reads the secret and tokens, and can replace the keys. `preset` and `identity_handler` apply the same rule to the metadata they are given, so metadata built without `discover` cannot skip it. For local development, pass `allow_insecure_http=True` to all three; each URL it lets through logs a WARNING.

Beyond the scheme, `discover` applies no host policy, so a self-hosted IdP on a private
network needs no opt-in. Whether a given issuer may be reached is a deployment question,
and a check on the URL string cannot answer it anyway — a hostname resolving to an internal
address passes any such test. Both `discover` and `identity_handler` accept a
`transport_factory`, which is where that policy belongs: it controls the actual outbound
connection, so a caller can pin DNS to validated addresses or route through its own egress.

#### What this preset does not do

Each is a deliberate limitation rather than an oversight:

| Limitation | Why |
| --- | --- |
| Confidential clients only | `preset` requires a client secret; a public (native/SPA) client cannot be configured, though `ProviderConfig` models one |
| No per-request `prompt` / `login_hint` / `max_age` / `acr_values` / `ui_locales` / `display` / `id_token_hint` | `extra_params` is fixed on a frozen config, so each would be one constant reused on every request |
| No RP-Initiated Logout | `end_session_endpoint` is neither read nor carried on `ServerMetadata` |
| No `response_mode` | The query default is always used |
| A signed (`application/jwt`) userinfo response is refused | Its signing algorithm is agreed at client registration, which the handler does not know, so it is refused rather than read unverified |

### Manual configuration

If your provider doesn't have a preset and doesn't implement OpenID Connect, configure it
directly.

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

`extra_params` adds fixed parameters to every authorization request. A parameter that binds the request to the client (`client_id`, `code_challenge`, `code_challenge_method`, `nonce`, `redirect_uri`, `resource`, `response_type`, `state`) or replaces it as a whole (`request`, `request_uri`) is refused when the config is built. Use the typed fields for `redirect_uri` and `resource` instead.

### Authorization URL

Build the URL to redirect the user to. State and PKCE are included automatically, and so is a nonce when the request asks for the `openid` scope. Keep the whole pending state, not only some of its fields.

```python
from apron_auth import OAuthClient

client = OAuthClient(config)
url, pending_state = await client.get_authorization_url(
    redirect_uri="https://yourapp.com/callback",
)
# Redirect the user to `url`.
# Keep `pending_state` server-side for the callback, where the user cannot change it.
```

### Code exchange

When the user comes back with an authorization code, exchange it for tokens. Pass the callback's `state` with the `pending_state`, and `exchange_code` refuses a `state` that does not match it. Keep the pending state where the user cannot change it, such as in a server-side session: every check in the exchange trusts it, so a pending state the user can replace defeats them all. A pending state saved as JSON comes back as a dict, so restore it with `OAuthPendingState.model_validate` before you pass it. Discard it after one exchange attempt. `exchange_code` refuses a pending state older than `max_pending_age_seconds` (ten minutes by default) in either mode, before it redeems the code. A `StateStore` that expires entries of its own can refuse one sooner (see below). With a `StateStore`, pass only `state` (see below).

When the authorization request asks for the `openid` scope, the authorization URL carries a nonce, and `exchange_code` raises `NonceValidationError` if the response carries no ID token, or one that does not carry the nonce. A custom `StateStore` must therefore keep the pending state's `nonce`. This binds the ID token to the request your application started, even when the provider does not enforce PKCE. `exchange_code` also raises `IdTokenValidationError` if the ID token's audience does not name your client, or names other parties without your client as the authorized party, or the token has expired, or it names another issuer when the config has one (OpenID Connect Core section 3.1.3.7). Either way the response's tokens are revoked first. The signature is not checked there, which the specification allows for a token received from the token endpoint over TLS; the OpenID and Microsoft identity handlers verify it.

```python
tokens = await client.exchange_code(
    code="authorization-code-from-callback",
    state="state-from-callback",
    pending_state=pending_state,
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
    state="state-from-callback",
    pending_state=pending_state,
)
identity = await client.fetch_identity(tokens)
print(identity.provider)        # "google", "github", etc.
print(identity.email)
print(identity.email_verified)
```

`fetch_identity` takes the `TokenSet` from `exchange_code` (or
`refresh_token`). It is narrowed to an `IdentityMaterial` — exposing
only the access token and, for OIDC providers, the ID token — before
being handed to the provider's identity handler, so handlers never
receive the refresh token or caller context.

Built-in identity handlers are inferred from standard Google, GitHub, HubSpot, Microsoft, Atlassian, Typeform, Salesforce, Notion, and Linear endpoint hostnames, so they apply to both the bundled `preset(...)` configs and any manually constructed `ProviderConfig` pointing at those hosts. A config with `allow_identity_inference=False` gets no inferred handler. The generic OpenID preset and `mcp.to_provider_config` set it that way. For other providers, pass a custom `identity_handler` to `OAuthClient`.
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
| `()`           | GitHub OAuth Apps, Typeform, consumer Google, personal Microsoft, Microsoft B2B guests |
| 1 entry        | Slack, Linear, Notion, single-domain Microsoft Entra, Salesforce, HubSpot, Google Workspace |
| Many entries   | Atlassian (Jira, Jira Service Management, Confluence); Microsoft Entra tenants with several verified domains |

Each `TenancyContext` exposes four normalized fields — `id`, `name`,
`domain`, `owns_email_domain` — plus a provider-specific `raw` payload
for fields that do not normalize cleanly. **Each normalized field may
independently be `None` (or `False` for `owns_email_domain`)** when
the provider's response does not assert that fact (for example,
Microsoft Entra workforce sign-in populates `id`, `name`, and `domain`
with `owns_email_domain=True` for each admin-verified domain of the
validated tenant; Google Workspace populates `domain` from the `hd`
claim and sets `owns_email_domain=True`; HubSpot populates only `id`
and `domain` with `owns_email_domain=False`). Persist `id` as the canonical key —
provider-mutable handles like Linear's `urlKey` should not be treated
as permanent identifiers.

```python
identity = await client.fetch_identity(tokens)
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
identity = await client.fetch_identity(tokens)
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
`IdentityProfile.owns_domain()`. This returns `True` only when the
provider asserts that some tenancy controls that domain (Google
Workspace via the `hd` claim, or Microsoft Entra workforce sign-in via
the validated tenant's admin-verified domains; capability flag below).
Gate on the `False` case to refuse domain-based grants:

```python
def join_org(identity: IdentityProfile, claimed_domain: str) -> Membership:
    domain = claimed_domain.strip().lower()
    if not identity.owns_domain(domain):
        raise AuthError(f"No domain-owning assertion for {domain}")
    return grant_membership(identity.identity_key(), domain)
```

Matching is exact once whitespace is trimmed and case is folded. A
parent domain does not confer ownership of its subdomains — a tenant
verified for `acme.com` does not satisfy a gate on `corp.acme.com`.

`owns_domain()` folds its argument for the comparison only; it does not
hand back a canonical form. Whatever key you persist is yours to
normalize. Canonicalize once and use that value for both the gate and
the write, as above — otherwise `" Example.COM "` passes the gate and
is then stored alongside `example.com` as a second membership row.

**Test the domain; do not pick one.** A single tenant can assert
several domains at once: every Entra tenant has an
`*.onmicrosoft.com` domain alongside any custom domain, and Microsoft
Graph does not guarantee the order it lists them in. Reducing that set
to one entry and comparing against it yields an arbitrary answer, and
persisting the reduction latches the arbitrary choice permanently:

```python
# DON'T — arbitrary which domain you get on a multi-domain tenant
owner = identity.domain_owning_tenancies()[0]
if owner.domain != claimed_domain:
    raise AuthError(...)
```

To enumerate or display the full set rather than test one domain, use
`domain_owning_tenancies()`, which returns every asserting tenancy:

```python
verified = [t.domain for t in identity.domain_owning_tenancies()]
# ["contoso.com", "contoso.co.uk", "contoso.onmicrosoft.com"]
```

Microsoft's assertion resolves the tenant's admin-verified domains from
a live directory call, so it can be withheld transiently — an outage,
throttling, or a tenant that has not consented leaves `tenancies=()`
and logs a warning rather than failing the sign-in. The assertion is
never fabricated, so the failure closes a domain gate rather than
opening one, but a consumer that *persists* the result should re-resolve
it rather than treating one absent assertion as durable. The extra call
needs no consent beyond the `User.Read` scope already in the preset's
`BASE_SCOPES`.

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
| Microsoft    | `True`                        | Validated ID token + tenant's admin-verified domains (workforce) |
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
        identity.owns_domain("example.com")
        and identity.verified_email() in ADMIN_EMAILS
    )
```

Without the `owns_domain()` check, any provider returning
`email_verified=True` for `founder@example.com` would grant admin —
including a personal GitHub account that happens to have
`founder@example.com` verified on it.

### Deprovisioning

When a user is offboarded by the IdP that controls their email's
domain (the Workspace admin disables the account, for example), the
provider's tokens stop refreshing. Consumers wanting their app
sessions to reflect that change in near-real-time must refresh on a
cadence shorter than the staleness window they are willing to accept.

apron-auth does not enforce refresh cadence. The recommended shape is:

- Issue your own short-lived application session (e.g. a JWT with a
  TTL of minutes, not hours).
- On session refresh, call `client.refresh_token(...)` against the
  provider; if refresh fails with an error that is not `retryable`,
  revoke the application session.
- For long-running background tasks that hold a refresh token, run
  the same check periodically.

There is no analogous deprovisioning path for providers that lack
domain-ownership (everything in the capability table above with
`False`). For those providers, deprovisioning at the OAuth layer
relies on the *user* revoking their authorization with the provider,
or the consumer maintaining an out-of-band revocation list.

### Token refresh

Refreshing can fail for good (the user revoked access, the client was deregistered) or for now (network blip, provider outage, rate limit). Every error says which through `retryable`, and `error_code` carries the provider's OAuth error code when it sent one.

```python
from apron_auth import TokenRefreshError

try:
    tokens = await client.refresh_token(tokens.refresh_token)
except TokenRefreshError as exc:
    if exc.retryable:
        ...  # try again later
    else:
        ...  # the grant is dead or the client is misconfigured: delete the token and re-authenticate
```

RFC 6749 defines every token-endpoint error code as a fault in the request as sent, so a code is not retryable unless it is `server_error` or `temporarily_unavailable`. If your provider uses a non-standard code for a temporary condition, add it:

```python
client = OAuthClient(
    config,
    retryable_error_codes={"rate_limited"},
)
```

These merge with the defaults, which `OAuthClient.DEFAULT_RETRYABLE_ERROR_CODES` holds. A provider that rotates refresh tokens may have consumed the token before an outage was reported, so a retry that then fails with `invalid_grant` needs a new sign-in. The code exchange classifies the same codes the same way, so `TokenExchangeError` carries the same `kind` and `error_code`, but it is never `retryable`: an authorization code is single-use, and presenting it twice can revoke the tokens it issued.

### Token revocation

```python
client = OAuthClient(config, revocation_handler=revocation_handler)
await client.revoke_token(tokens.access_token)
```

### State management

If you need to persist OAuth state across requests (e.g. between the redirect and the callback), implement the `StateStore` protocol. `exchange_code` enforces `max_pending_age_seconds` itself, so a store expires entries only to bound its own storage. `MemoryStateStore` expires one at its `max_age`, ten minutes by default, so with it the shorter of the two limits applies.

```python
from apron_auth import StateStore, OAuthPendingState

class MyStateStore:
    async def save(self, state: OAuthPendingState) -> None:
        # Persist state, keyed by state.state.
        ...

    async def consume(self, state_key: str) -> OAuthPendingState | None:
        # Look up and invalidate in one step. Return None if it's missing, or if your store expired it.
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

If your application needs to carry context through the OAuth flow (e.g. which user or tenant initiated it), pass `metadata` when building the authorization URL. apron-auth carries it opaquely on the pending state, through the `StateStore` or the `pending_state` you pass back, and surfaces it on `TokenSet.context` after the exchange.

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

## Connecting to an MCP server

When the provider is not a known preset but a remote MCP (Model Context Protocol) server, `apron_auth.mcp` discovers its OAuth configuration at runtime (RFC 9728 protected-resource metadata + RFC 8414 authorization-server metadata) and, where the server supports it, registers a client dynamically (RFC 7591). The result folds into the same `ProviderConfig`/`OAuthClient` used everywhere else.

```python
from apron_auth import OAuthClient, mcp

# 1. Discover the server's OAuth endpoints.
meta = await mcp.discover("https://mcp.example.com", transport_factory=my_transport_factory)

# 2. Obtain a client identity, in the spec's priority order.
if my_pre_registered_client_id:  # an existing relationship with this server
    client_id, client_secret = my_pre_registered_client_id, my_pre_registered_secret
    registered_auth_method = None
elif meta.supports_cimd:  # CIMD — the forward path; you host the metadata document
    client_id = mcp.cimd_client_id("https://app.example.com/oauth/client-metadata.json")
    client_secret = None
    registered_auth_method = None
elif meta.registration_url:  # DCR — deprecated, kept for backward compatibility
    reg = await mcp.register_client(meta.registration_url, redirect_uri, transport_factory=my_transport_factory)
    client_id, client_secret = reg.client_id, reg.client_secret
    registered_auth_method = reg.token_endpoint_auth_method
else:
    raise RuntimeError("server offers no supported client-registration mechanism")

# 3. Build a ProviderConfig and drive the normal authorization-code flow.
config = mcp.to_provider_config(
    meta,
    client_id=client_id,
    client_secret=client_secret,
    registered_auth_method=registered_auth_method,
    redirect_uri=redirect_uri,
)
client = OAuthClient(config, transport_factory=my_transport_factory)
url, pending = await client.get_authorization_url()
# Redirect the user to `url`; on the callback, pass the `iss` query
# parameter so the issuer can be validated before the code is redeemed:
tokens = await client.exchange_code(
    code="code-from-callback",
    state="state-from-callback",
    pending_state=pending,
    iss="iss-from-callback",
)
```

The config that `to_provider_config` returns sets `allow_identity_inference=False`, so `fetch_identity` raises `IdentityNotSupportedError` unless you pass an `identity_handler` to `OAuthClient`. Inference would otherwise give an authorization server on a built-in provider's host that provider's handler, which sends the MCP server's access token to that provider's API.

A `ProviderConfig` that you build by hand from `discover` output allows inference by default, so set `allow_identity_inference=False` on it yourself. Pass a handler for the MCP server's own identity contract. Pass a built-in handler, such as `linear.LinearIdentityHandler()` from `apron_auth.providers`, only when that provider's API accepts the MCP server's tokens.

Public clients are supported end to end: a server that issues no secret yields `ClientRegistration.client_secret = None`, and `to_provider_config` sets `token_endpoint_auth_method` to `"none"`.

When using CIMD, you host the `client-metadata.json` yourself at the `client_id` URL — apron-auth is stateless and does not host it. The document must include `client_id`, `client_name`, and `redirect_uris`. Its `client_id` must equal that URL, and its `redirect_uris` must include the redirect you use in the flow; the authorization server fetches and validates the document. `mcp.cimd_client_id(url)` checks the URL is a well-formed CIMD identifier (`https` scheme, a document path, no userinfo or fragment); it does not fetch the URL.

Unlike DCR or pre-registered credentials — which are bound to the authorization server that issued them and must be re-registered when that server changes — a CIMD `client_id` is a self-hosted URL, portable across authorization servers with no re-registration.

`discover` refuses authorization server metadata whose `issuer` is not the server the document was fetched from (RFC 8414 section 3.3), records that issuer, and `to_provider_config` carries it onto the `ProviderConfig`. Pass the callback's `iss` parameter (RFC 9207) to `exchange_code` and it is validated against that issuer **before** the code is redeemed, refusing an authorization-server mix-up. When the server advertises `iss` support, a callback that omits `iss` is also rejected. Presets carry no issuer and are unaffected.

Passing `registered_auth_method` lets the server's per-client choice (RFC 7591) win over the derivation from the advertised set — for example a server that supports both `client_secret_post` and `client_secret_basic` but registers a given client as `basic`-only. Omit it (or pass `None`) to derive the method from the client's secret and the server's advertised set.

### SSRF safety

Discovery, registration, the token request, and token revocation all fetch URLs taken from server-supplied metadata. `discover`, `register_client`, and `OAuthClient` each accept a **`transport_factory`** (`Callable[[str], httpx.AsyncBaseTransport]`) so the caller controls the actual outbound connection; the `OAuthClient` factory governs both the token request and revocation. For an **untrusted** `server_url` — for example one a user pasted — supply a transport that resolves DNS once and pins the connection to validated public addresses. The built-in HTTPS-only requirement and non-public-IP-literal block are defense-in-depth; they do **not** stop a hostname that resolves to an internal address. A `url_validator` hook is also accepted for URL-string policy.

## Verifying workload identity tokens

A workload on Google Cloud, GitHub Actions or Kubernetes can fetch a token its platform signed, naming the workload and an audience it chose. A server that trusts the platform can accept that token in place of a secret the workload would otherwise hold, as the OAuth 2.0 JWT bearer grant does (RFC 7523). `apron_auth.workload` is the server side of that: it checks the token, and the server decides what the identity it names may do.

```python
from apron_auth.errors import IdentityFetchError, TokenExpiredError, TokenValidationError
from apron_auth.workload import WorkloadTokenVerifier

verifier = WorkloadTokenVerifier("https://accounts.google.com", transport_factory=my_transport_factory)

try:
    identity = await verifier.verify(token, audience="https://gateway.example.com")
except TokenExpiredError:
    ...  # tell the workload to fetch a fresh token
except TokenValidationError:
    ...  # refuse the token; retrying it cannot succeed
except IdentityFetchError:
    ...  # the issuer is unreachable; ask the workload to retry later

identity.subject  # the platform's stable identifier for the workload
identity.email  # set only when the token marks it verified, as Google does for a service account
```

The issuer's signing keys are found through its OpenID configuration document, of which only `issuer` and `jwks_uri` are read, so an issuer with no authorization endpoint, as most workload issuers are, is discovered too. Pass `jwks_url` to skip discovery. The document is read once, so an issuer that moves its key set needs a new verifier. The keys are kept for an hour, and a token no cached key verifies refetches them early, at most once a minute. Only public-key algorithms are accepted, and a published RSA key shorter than 2048 bits is skipped, here and in every OpenID sign-in. `iss` must name the issuer exactly, and `sub`, `aud`, `exp` and `iat` are required.

`audience` is required. Pass the audience your server answers to, or several of which the token must name one; an empty collection is a `ConfigurationError`, because it would accept every audience. `audience=None` checks only that the token names some audience, for a server that matches the audience itself, for example against rules it stores. Such a server must then match it before trusting the token, because a token minted for another service would otherwise pass.

A matching audience proves the token was minted for your server, not that the workload is one you trust: on a shared platform anyone can mint a token for any audience, so any Google Cloud service account or any GitHub repository can present one. Decide what the token may do from its subject and the claims that name its owner. Prefer a platform's immutable identifiers to names that can be reused, such as GitHub's `repository_id` and `repository_owner_id` over a `sub` built from the repository name, which a renamed or recreated repository takes over.

The configuration document and key set URLs are fetched through `transport_factory`, as in [SSRF safety](#ssrf-safety). The issuer is the caller's, but the key set URL comes from the issuer's document.

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
| Any OpenID | `oidc.preset(...)`       | RFC 7009 POST, if advertised | `False`              |

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

All exceptions inherit from `OAuthError`. The class says which step failed. Every error also carries a `kind`, a `FailureKind` that says what went wrong in a form code can read, and `retryable`, which is `True` when the same request may succeed later without any change.

| `kind`          | Meaning                                                                                  | `retryable` |
|-----------------|------------------------------------------------------------------------------------------|-------------|
| `CONFIGURATION` | Your configuration or an argument cannot work.                                           | no          |
| `REFUSED`       | apron-auth refused what the other side sent: a token, a document or a response that does not validate. | no |
| `REJECTED`      | The other side refused the request as sent: a client error status or an OAuth error code. | no          |
| `SERVER_ERROR`  | The other side answered with a server error or a rate limit.                             | yes         |
| `TIMEOUT`       | The request ran out of time.                                                             | yes         |
| `UNEXPECTED`    | An error apron-auth does not classify, such as a fault in a handler you supplied.        | no          |
| `UNREACHABLE`   | The other side could not be reached.                                                     | yes         |

| Exception                      | When it's raised                                                                                                |
|--------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `TokenExchangeError`           | Code exchange failed: the token endpoint refused the code, or its response was refused. Carries `error_code`. Never `retryable`: a code is single-use, so start a new authorization. |
| `IdTokenValidationError`       | The ID token is unreadable, names another audience, authorized party or issuer, or has expired. Subclass of `TokenExchangeError`. |
| `NonceValidationError`         | The response has no ID token, or it lacks the nonce, or the pending state lost it. Subclass of `IdTokenValidationError`. |
| `TokenRefreshError`            | Refresh failed. `retryable` tells an outage from a dead grant, and `error_code` tells a dead grant (`invalid_grant`) from a client fault. |
| `RevocationError`              | The revocation request could not be sent, or the provider refused it.                                           |
| `StateError`                   | OAuth state was missing, invalid, expired, already used, or did not match the pending state.                    |
| `ConfigurationError`           | Something's wrong with the provider config (e.g. missing `redirect_uri`), or an argument you passed cannot work — such as an MCP server or registration URL this library refuses. |
| `IdentityNotSupportedError`    | No identity handler exists for this provider configuration. Subclass of `ConfigurationError`.                  |
| `McpDiscoveryError`            | MCP OAuth metadata discovery failed — a blocked or rejected URL the server's metadata declares, or unreachable or malformed server metadata. A URL you passed raises `ConfigurationError` instead. |
| `McpRegistrationError`         | MCP OAuth dynamic client registration (RFC 7591) failed at the server.                                          |
| `OidcDiscoveryError`           | Reading an OpenID provider's configuration document failed, or the document named a different issuer.           |
| `IdentityFetchError`           | Fetching the user's identity failed. `kind` tells an outage from a refusal.                                     |
| `IdentityScopeNotGrantedError` | The token lacks a scope the identity endpoint needs. Subclass of `IdentityFetchError`.                          |
| `TokenValidationError`         | An ID token or workload token was refused. `reason` says why: `audience`, `claims`, `expired`, `malformed`, `signature`, `unknown_issuer`, `unknown_key` or `unsupported`. Subclass of `IdentityFetchError`, so catch it first. |
| `TokenExpiredError`            | An ID token or workload token verified but has expired. Subclass of `TokenValidationError`.                     |

`TokenExchangeError` and `TokenRefreshError` share the `TokenEndpointError` base, which is where `error_code` lives.

### Migrating from 0.18

- `PermanentOAuthError` is gone. Catch `TokenRefreshError` and read `retryable`; a dead grant has `retryable == False` and `error_code == "invalid_grant"`.
- `permanent_error_codes` on `OAuthClient` is now `retryable_error_codes`, and the default changed: a code you do not list is not retryable.
- `TokenVerificationError` is now `TokenValidationError` and requires a `reason`.
- `IdentityNotSupportedError` is a `ConfigurationError`, not a sibling of `IdentityFetchError`.
- A `RevocationError` or `IdentityFetchError` your own handler raises should pass `kind`, or declare `default_kind` on a subclass. One raised without a kind is `UNEXPECTED`, which is never retryable.
- `StandardRevocationHandler` raises `RevocationError` with the status's `kind` for an error status. It no longer returns `False`.
- `TokenExchangeError.retryable` is always `False`. Start a new authorization instead of repeating an exchange.
- `mcp.discover` and `mcp.register_client` raise `ConfigurationError` for a URL you passed that they refuse — the server URL, the resource-metadata hint, or the registration endpoint — including one the HTTP client cannot send. A URL the server's metadata declares still raises `McpDiscoveryError`.
- Errors can be pickled and keep `kind`, `error_code` and `reason`.

## Logging

apron-auth logs through the standard library and configures nothing on
your behalf. It attaches a `NullHandler` to its root logger, so it stays
silent until your application opts in — without one, Python's last-resort
fallback would write warnings to your stderr.

Loggers are named after their module, so the `apron_auth` logger is the
single point of control for the whole library:

```python
import logging

logging.getLogger("apron_auth").setLevel(logging.WARNING)
logging.getLogger("apron_auth").addHandler(my_handler)

# Or target one module.
logging.getLogger("apron_auth.providers.microsoft").setLevel(logging.DEBUG)
```

| Logger                           | Emits                                                       |
|----------------------------------|-------------------------------------------------------------|
| `apron_auth.client`              | Refused tokens that could not be revoked.                    |
| `apron_auth.stores`              | Expired OAuth state discarded on lookup.                     |
| `apron_auth.providers.microsoft` | Withheld tenancy assertions.                                 |
| `apron_auth.providers._jwks`     | Signing key set refresh failures and skipped keys.           |
| `apron_auth.providers.atlassian` | Person-level profile withheld after a User Identity API failure. |
| `apron_auth.providers.github`    | Grant revocation the provider did not confirm.               |
| `apron_auth.providers.hubspot`   | Revocation returning an unexpected status.                   |
| `apron_auth.providers.notion`    | Revocation returning an unexpected status.                   |
| `apron_auth.providers.oidc`      | Insecure `http` allowed by opt-in; no PKCE advertised; userinfo failure degraded; a refused discovery redirect (DEBUG). |

Two levels are used. `WARNING` marks a capability that degraded without
raising — a revocation the provider would not confirm, or a
domain-ownership assertion withheld because a directory lookup failed.
Both deserve an operator's attention precisely because they do not
surface as exceptions: the call returns, and the effect is silent. A
withheld assertion in particular makes domain-gated access refuse.
`DEBUG` carries diagnostic detail: expired state, and provider response
parsing that is useful when a response format changes.

There is no `logger` parameter to inject. The logging hierarchy is the
injection point: because every module logs to its own `__name__`,
configuring `apron_auth` reaches all of them, and adapters, filters, and
`contextvars` compose with it in the usual way.

### What is never logged

Access tokens, refresh tokens, client secrets, and ID-token payload bytes are never written to logs at any level. Exception *values* are not logged either — in their place goes whichever non-sensitive primitive actually carries diagnostic signal, such as an HTTP status code or an exception class name. Where no such primitive is at hand, the line is fixed text only. A raised exception's rendering can embed the request that carried a credential, and for some providers a token travels in the URL path, so the exception value is not safe to emit generically.

This is a contract, not an implementation detail: if you find a
credential in log output, treat it as a bug and report it.

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
