# apron-auth

Stateless OAuth 2.0 protocol library with PKCE, token refresh, and provider-specific revocation.

## What is apron-auth?

Provider-specific OAuth knowledge — endpoints, auth methods, PKCE quirks, error classification, and revocation — encoded as a library so your application doesn't have to maintain it.

| What                 | Why                                                                                                                                       |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| Provider presets     | Endpoints, auth methods, PKCE toggles, scope separators, and revocation for multiple providers out of the box.                            |
| Error classification | Distinguishes permanent failures (revoked token, invalid client) from transient ones so callers know whether to retry or re-authenticate. |
| Revocation support   | Providers all revoke differently (POST, DELETE, GET, Basic auth, query params) — presets include the right handler when available.          |
| Auth method handling | `client_secret_post`, `client_secret_basic`, or a public client — picked from your config and sent as configured.                          |
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

Presets bundle the endpoints, auth method, PKCE config and provider name for a given provider into a single call, and the client reads the revocation handler from the name.

```python
from apron_auth.providers import google

config = google.preset(
    client_id="your-client-id",
    client_secret="your-client-secret",  # pragma: allowlist secret
    scopes=["openid", "email", "profile"],
)
```

If you use [apron-tools](https://github.com/mozilla-ai/apron-tools), scopes come from capability groups instead of being hardcoded:

```python
from apron_tools.providers.google.gmail.scopes import CAPABILITY_GROUP as GMAIL

config = google.preset(
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

config = oidc.preset(
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
discovered issuer carries onto the config. The authorization-response `iss` (RFC 9207) rides on the
`AuthorizationCallback` and is validated before a code is redeemed, whenever the provider
sends `iss` or advertises `authorization_response_iss_parameter_supported`. An ID token whose `iss` differs from the
configured issuer is refused at the code exchange, and its tokens are revoked.

Entra needs a tenant-specific issuer such as `https://login.microsoftonline.com/<tid>/v2.0`.
The `/common` and `/organizations` documents name a templated issuer, which fails the issuer
match by design.

Always pass the identity handler explicitly, as above. The config that `preset` returns names no built-in provider and allows no provider's identity handler, so `fetch_identity` raises `IdentityNotSupportedError` without a handler. The endpoint hosts select nothing. A config on an Entra or Google host would otherwise get that provider's handler, with `provider` set to `microsoft` or `google` instead of `oidc:<issuer>`, and a different `identity_key()` for every user.

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

`discover` requires an absolute `https` URL for the issuer, the document URL, the signing key set, and every endpoint the document names (no fragment; the issuer also has no query or userinfo, per Discovery 1.0 section 4.1; a bad value raises `OidcDiscoveryError` naming the field), because the client secret and every token travel over them and the signing key set authenticates every ID token: over `http`, an on-path attacker reads the secret and tokens, and can replace the keys. `preset` and `identity_handler` apply the same rule to the metadata they are given, so metadata built without `discover` cannot skip it. For local development, pass `allow_insecure_http=True` to all three; each URL it lets through logs a WARNING. A `ServerMetadata` you build by hand holds its endpoints to the same rule, so one carrying a plain-HTTP URL off loopback has to come from `ServerMetadata.unsafe.allow_plain_http`.

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

`extra_params` adds fixed parameters to every authorization request. A parameter that binds the request to the client (`client_id`, `code_challenge`, `code_challenge_method`, `nonce`, `redirect_uri`, `resource`, `response_type`, `state`) or replaces it as a whole (`request`, `request_uri`) is refused when the config is built. The same names are refused in the `authorize_url` query, because the request sets each of them itself and drops one the URL carries, so a config that stated one would never send it. Use the typed fields for `redirect_uri` and `resource` instead.

Every model here is frozen, so one field is changed by building another. `config.with_changes(scopes=["read"])` returns a copy that ran every rule the model enforces, and raises `ConfigurationError` for a change those rules refuse. It also refuses an update naming no field, so a misspelled name cannot pass for a change; a change to `provider`, because the label decides which rules a config is held to and which hosts a token may be sent to; and re-pointing a URL that `unsafe.allow_plain_http` waived, because a waiver was stated for the URL it accepted, and pointing it elsewhere would state one no code stated. Pydantic's own `model_copy`, `model_construct` and the `copy` functions run no validator, so an instance built through one of them carries values the model would refuse. The rules that decide where a credential is sent are checked again where the request is built, so such an instance is refused there rather than reaching a provider.

### Authorization URL

Build the URL to redirect the user to. State and PKCE are included automatically, and so is a nonce when the request asks for the `openid` scope. Keep the whole pending state, not only some of its fields.

`OAuthClient` hands the pending state back to you to keep. A browser flow has nowhere to hold it between the redirect and the callback, so it uses `StoredStateClient` and a `StateStore` instead, which the next section shows. Do not return the state to the browser to compare there instead: a server that leaves the comparison to the browser redeems whatever code reaches its callback. `StoredStateClient` compares it server-side and binds the flow to the browser it built the URL for, which the next section shows.

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

When the user comes back, exchange the authorization response for tokens. Pass the whole response as an `AuthorizationCallback`, and `exchange_code` reads every parameter it needs off it: it refuses a `state` that does not match the pending state, validates `iss` against the configured issuer, and refuses a response that states no code before it consumes anything. It also refuses a pending state older than `max_pending_age_seconds` (ten minutes by default) before it redeems the code. A `StateStore` that expires entries of its own can refuse one sooner (see below).

When the authorization request asks for the `openid` scope, the authorization URL carries a nonce, and `exchange_code` raises `NonceValidationError` if the response carries no ID token, or one that does not carry the nonce. A custom `StateStore` must therefore keep the pending state's `nonce`. This binds the ID token to the request your application started, even when the provider does not enforce PKCE. Whether the nonce rule applies at all is the request's own answer, recorded on the pending state as `openid_requested` when the URL was built, so a scope change between the request and the exchange does not change the outcome. A store must keep that field beside the nonce, and a stored state whose two disagree is refused as it is restored, because a nonce the store lost would otherwise read as a request that asked for none. `exchange_code` also raises `IdTokenValidationError` if the ID token's audience does not name your client, or names other parties without your client as the authorized party, or the token has expired, or it names another issuer when the config has one (OpenID Connect Core section 3.1.3.7). Either way the response's tokens are revoked first. The signature is not checked there, which the specification allows for a token received from the token endpoint over TLS; the OpenID and Microsoft identity handlers verify it.

Where the pending state comes from is a property of the client you built, not something to remember at the call site. A client that holds a `StateStore` takes the callback alone. A client that does not takes the pending state with it.

A browser flow serves the redirect and the callback from two separate requests, so the pending state belongs in a `StateStore` (see below) and the client is a `StoredStateClient`.

The store settles that the `state` was minted by this application, has not expired, and is spent once, so a code presented with a state this application never issued, and a state presented twice, are both refused. `StoredStateClient` settles which browser may present the callback as well: `get_authorization_url` mints a `browser_token` and sends the `state` derived from it, and `exchange_code` refuses a callback whose `state` that token does not mint, before it consumes the store and before it calls the token endpoint. RFC 6749 section 10.12 asks a client for that binding, and without it an attacker who completes a provider login with their own account can send the resulting callback URL to a victim: the victim's request redeems the attacker's code, and an application that signs the victim in with those tokens has signed them in as the attacker. PKCE does not help there, because the stored code verifier belongs to the attacker's own flow.

`get_authorization_url` returns a `BrowserBoundAuthorization`, carrying the URL, the `state` the request sends, and the `browser_token`. The token itself never travels to the provider: the request sends its SHA-256 as the `state`, which reveals nothing the token can be recovered from. The pending state stays in the store, so the model carries no PKCE verifier beside the token. Keep the token where only the browser it was minted for can present it, out of the authorization URL and out of any page the browser renders, and drop it once the exchange returns.

A `Secure`, `HttpOnly`, `SameSite=Lax` cookie is the usual place. Name it with the `__Host-` prefix so no other host on the same site can write it, and set `Secure`, `Path=/`, and no `Domain`, because a browser honors that prefix on nothing else and drops such a cookie without a word. Give it a `Max-Age` no longer than `max_pending_age_seconds`, since the exchange refuses an older pending state anyway. One fixed name per callback route is enough while a browser runs one flow at a time to that route: a second flow started in the same browser overwrites the name, so the first callback is refused and that user starts again. To let two run at once, put the `state` in the cookie name, `__Host-flow-{authorization.state}` where you set it and `__Host-flow-{callback.state}` where you read it, because the callback carries the `state` and nothing else of yours. `SameSite=Lax` suits the authorization-code redirect, which reaches you as a top-level GET. A provider answering with a POST to your redirect URI, as `response_mode=form_post` asks for, sends no `Lax` cookie at all, so a flow configured that way needs `SameSite=None` with `Secure`.

```python
from apron_auth import AuthorizationCallback, StoredStateClient

store = MyStateStore()
client = StoredStateClient(config, store)

authorization = await client.get_authorization_url(redirect_uri="https://yourapp.com/callback")
# Redirect the user to `authorization.url`. The store holds the pending state.
# Set `authorization.browser_token` in the cookie, and read it back as `cookie_browser_token`.

# `query` is the callback's query parameters: your framework's own query
# mapping, or any mapping of the names to their values.
callback = AuthorizationCallback.from_query(query)
tokens = await client.exchange_code(callback, browser_token=cookie_browser_token)
print(tokens.access_token)
print(tokens.refresh_token)
```

A callback that reaches your redirect URI with no such cookie is refused with `StateError`, the same refusal as a callback whose `state` the token does not mint. Both mean the callback cannot be bound to a browser, and neither consumes the store nor redeems the code.

A flow that one process spans, such as a native or command-line sign-in, can hold the pending state itself and use `OAuthClient`. Keep it where the user cannot change it, such as in a server-side session: every check in the exchange trusts it, so a pending state the user can replace defeats them all. A server-side session is already keyed to one browser, so holding the pending state there binds the flow to that browser as well, which is what the browser token gives the store-backed flow above. A pending state saved as JSON comes back as a dict, so restore it with `OAuthPendingState.model_validate` before you pass it. The dict must hold the model's own fields and nothing else, because a field the model does not define is refused rather than ignored. A store that adds bookkeeping of its own, such as a document identifier or an expiry attribute, therefore needs those keys dropped first: select the model's fields out of the stored record instead of passing the whole record. Discard it after one exchange attempt, because only a `StateStore` refuses a pending state that is reused.

```python
from apron_auth import AuthorizationCallback, OAuthClient

client = OAuthClient(config)
url, pending_state = await client.get_authorization_url(redirect_uri="https://yourapp.com/callback")

callback = AuthorizationCallback.from_query(query)
tokens = await client.exchange_code(callback, pending_state=pending_state)
print(tokens.access_token)
print(tokens.refresh_token)
```

### Identity fetch (optional)

If you need normalized identity fields for login or account-linking flows,
fetch them after token exchange:

```python
tokens = await client.exchange_code(
    AuthorizationCallback.from_query(query), pending_state=pending_state
)
identity = await client.fetch_identity(tokens)
print(identity.provider)        # google, github, etc. (a Provider member for a built-in provider)
print(identity.email)
print(identity.email_verified)
```

`fetch_identity` takes the `FreshTokenSet` that `exchange_code` and
`refresh_token` return, and nothing else. An identity handler may accept
the ID token in it without a signature check, which is safe only for a
token the token endpoint returned over TLS, so a `TokenSet` reloaded
from storage is a type error and raises `ConfigurationError`. Persist
the fields as before. A stored set comes back as a plain `TokenSet`, and
`refresh_token` turns it into a fresh one; when the provider issued no
refresh token, run authorization again. Restore it with
`TokenSet.model_validate`, and pass the model's own fields and nothing
else: a field the model does not define is refused rather than ignored,
and a `UserToken` nested in the record is held to the same rule. If your
store adds keys of its own, select the model's fields out of the record
first. A model you persist must hold a `TokenSet`, not a
`FreshTokenSet`: reloading a `FreshTokenSet` field from storage raises
`ConfigurationError`. The fresh set is narrowed to an `IdentityMaterial`
— exposing only the access token and, for OIDC providers, the ID token —
before being handed to the provider's identity handler, so handlers
never receive the refresh token or caller context. Each token on it is a
`SecretToken`, as is the token `revoke_token` and a `RevocationHandler`
take, so a handler unwraps one with `get_secret_value()` into the request
it sends and binds the unwrapped value to no variable of its own. A
`SecretToken` states nothing as text, so formatting one or sending one
without that call raises `TypeError` rather than sending a masked value a
provider would accept. See [what an error reporter can
capture](#what-an-error-reporter-can-capture).

A built-in identity handler comes from the provider the config names. Every bundled `preset(...)` names its own, and a `ProviderConfig` you build by hand gets one by passing `provider=Provider.GOOGLE` (or any other member). A config that names no provider gets no built-in handler, so `fetch_identity` raises `IdentityNotSupportedError` unless you pass an `identity_handler` to the client. The generic OpenID preset and `mcp.to_provider_config` name none, and neither does a hand-built config that leaves `provider` out. Setting `use_builtin_identity_handler=False` refuses the named provider's handler as well, which both of those presets also do. A config that names a provider whose host suffixes do not cover both its authorization and token endpoints constructs fine but is refused at `fetch_identity` with `ConfigurationError`, because an identity handler may derive the endpoint it sends the access token to from the config. Pass your own `identity_handler` for a deployment on other hosts, such as a Salesforce org on a custom login domain. The built-in Salesforce handler is not that handler, because it sends the access token only to a `salesforce.com` host, so a custom domain needs a handler of its own. For a provider this library does not know, pass a custom `identity_handler`.
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
provider's tokens can *in principle* carry a domain-owning tenancy. A
config that names a provider takes the answer from that provider, and a
config that names none carries its own. Consumers building a
domain-gated tenancy flow can reject incapable providers at startup,
rather than discovering the gap at login time:

```python
config = some_preset(client_id=..., client_secret=..., scopes=...)
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

Refreshing can fail for good (the user revoked access, the client was deregistered) or for now (network blip, provider outage, rate limit). Every error says which through `retryable`, and `error_code` carries the provider's OAuth error code when it stated one as a lowercase identifier.

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

An ID token in a refresh response is held to the same claims as the one the original sign-in carried, which OpenID Connect Core section 12.2 requires: the audience and authorized party must name your client, the issuer must match when the config has one, and the token must not have expired. A response refused for any of those raises `TokenRefreshError` with `kind` `REFUSED`, and its tokens are revoked first, except the refresh token you passed in, which you still hold. The specification also holds the ID token to the subject of the original, which this library does not keep, so comparing `sub` against the identity you stored is yours to do.

### Token revocation

```python
from apron_auth import SecretToken

client = OAuthClient(config)
await client.revoke_token(SecretToken(tokens.access_token))
```

The client revokes through the handler the config's provider needs, so a preset's config needs no handler passed with it. Google, GitHub, Slack, Notion and HubSpot each revoke their own way, and the rest take RFC 7009 revocation. A config that names no provider, such as one from `oidc.preset(...)` or `mcp.to_provider_config(...)`, takes RFC 7009 revocation through the client's `transport_factory`. Pass `revocation_handler=` to either client to revoke through a handler of your own instead; the handler classes stay public, and `apron_auth.providers.revocation_handler_for(config)` returns the one a config resolves to.

A revocation that fails says whether to try again. `RevocationError.retryable` is true for a rate limit or an outage and false for a refusal, so a caller that honors it does not abandon a token the same request would revoke a minute later. Every handler decides this the same way. A status the provider documents is read as that provider documents it, and any other failure status is read as [any failed response is](#error-hierarchy). A response stating when to come back states a temporary condition instead, whichever status carries it, so no handler reads such a response as one of its own statuses. A success status the provider does not document states no outcome at all, so it is refused as an answer this library cannot read rather than as the provider refusing. RFC 7009 revocation reads the 200 section 2.2 documents, and the 204 that states the same outcome carrying no body, so a server that only accepts the request for later is not reported as having completed it. Slack also reports its own outages, rate limits and workspace migrations as a success status with `ok=false`, and those are retryable too, while a body carrying no boolean `ok` states no outcome either. Slack states whether the token was revoked in a `revoked` member, and `ok` states only that the call succeeded, so a body stating `revoked` false is a failed revocation, and one stating no boolean `revoked` states no outcome.

A token a provider states is already invalid is reported as revoked, because the purpose of the request is then already achieved, as RFC 7009 section 2.2 reads it. GitHub and HubSpot read their own 404 that way, Google and Notion their own 400, and Slack the `account_inactive`, `token_expired` and `token_revoked` codes it names with a success status and `ok=false`. Google answers one status for every error condition and documents no error codes, so its body states nothing this library reads; its request names a token and nothing else, and one naming none is refused with `ConfigurationError` before it is sent, so that status states the token rather than the request. Reading it as revoked says the token is not usable, not that a grant behind it is gone.

GitHub's 422 is read less precisely than you may expect. GitHub answers it both for a validation failure and for a spam throttle, and nothing in the status tells them apart, so it reports a refusal and logs a WARNING.

A config whose provider exposes no revocation endpoint, such as Microsoft's or Typeform's, declares no `revocation_url`, and `revoke_token` refuses it with `ConfigurationError`. A config that names a provider must name that provider's host for revocation, or the host its token endpoint names, because a revocation request carries the token there. Construction refuses one that names another host, and the request refuses the host it is about to reach, so a handler that builds its URL per token, and a copy that rewrites the revocation endpoint past validation, are both held to the rule. A copy that rewrites the token endpoint as well states a different issuer, and the rule then holds it to that issuer rather than to the provider it is labeled with. A config that names no provider states no hosts to hold it to, and the caller passing one owns where its token is sent. The request also refuses a URL that does not state `https`, whatever provider the config names, unless the URL names a loopback host or the config waived plain HTTP for `revocation_url` through `ProviderConfig.unsafe.allow_plain_http`, and it refuses a URL carrying a credential in its authority, because an HTTP client presents that credential in place of the token.

### Timeouts

One policy bounds every request this library sends: the code exchange and the refresh, revocation, identity, discovery, the OpenID provider document, the signing key set, and MCP registration. `TimeoutPolicy` states two limits in seconds. `connect_seconds` bounds establishing a connection, and `request_seconds` bounds a whole request however many steps it takes. Each must be a positive finite number, so no limit can be turned off, and a connect limit longer than the request limit is refused rather than accepted and ignored. The defaults are 5 and 10.

A whole-request limit is not a per-step one. An HTTP client's own limits bound a single read or write, so a response arriving slowly in many steps outlives all of them. `request_seconds` bounds the request itself, and a request that passes it fails with the `TIMEOUT` failure kind.

The token, revocation and identity requests had no whole-request limit before 0.21.0, so a provider that takes longer than ten seconds in total now fails where it used to be waited on. Raise `request_seconds` for a provider known to be slow: a cold-starting self-hosted OpenID provider, an Atlassian identity lookup that fans out across a user's sites, or a HubSpot introspection call.

Set it where you build the configuration, and every request for that provider runs under it. Each builder takes it as a keyword, and a configuration written by hand takes it as a field:

```python
from apron_auth import OAuthClient, TimeoutPolicy
from apron_auth.providers import google

config = google.preset(
    client_id="...",
    client_secret="...",
    scopes=["openid", "email"],
    timeouts=TimeoutPolicy(connect_seconds=2.0, request_seconds=30.0),
)
client = OAuthClient(config)
```

The functions that run before a configuration exists take the same keyword, because they have none to read it from: `mcp.discover`, `mcp.register_client`, `oidc.discover` and `WorkloadTokenVerifier`.

A `RevocationHandler` or `IdentityHandler` of your own needs nothing new. It receives the configuration, so `config.timeouts` is the policy in force for the request it is about to send. A handler that ignores it bounds its own requests by nothing, and nothing in this library bounds them for it.

`ProviderConfig.revocation_cleanup_seconds` is a separate limit, because it bounds this library's own work rather than one request: when a token response is refused, the tokens it carried are revoked, and each revocation is canceled past that limit so the refusal is reported rather than waited on. It defaults to ten seconds. A revocation handler that does not stop when it is canceled can still delay the refusal, because this library waits for the cancellation it asked for.

### State management

If you need to persist OAuth state across requests (e.g. between the redirect and the callback), implement the `StateStore` protocol. `exchange_code` enforces `max_pending_age_seconds` itself, so a store expires entries only to bound its own storage. `MemoryStateStore` expires one past its `max_age`, ten minutes by default, drawing the boundary where the exchange draws it, so with it the shorter of the two limits applies.

```python
from apron_auth import OAuthPendingState, StateStore, StoredStateClient

class MyStateStore:
    async def save(self, state: OAuthPendingState) -> None:
        # Persist state, keyed by state.state.
        ...

    async def consume(self, state_key: str) -> OAuthPendingState | None:
        # Look up and invalidate in one step. Return None if it's missing, or if your store expired it.
        ...

client = StoredStateClient(config, MyStateStore())
authorization = await client.get_authorization_url(
    redirect_uri="https://yourapp.com/callback",
)

# When the callback arrives, pass the response and the token of the browser
# presenting it. The store is consumed automatically, because the response
# carries the state it was sent.
tokens = await client.exchange_code(
    AuthorizationCallback.from_query(query), browser_token=cookie_browser_token
)
```

#### Carrying context through the flow

If your application needs to carry context through the OAuth flow (e.g. which user or tenant initiated it), pass `context` when building the authorization URL. apron-auth carries it opaquely on `OAuthPendingState.context`, through the `StateStore` or the `pending_state` you pass back, and surfaces it on `TokenSet.context` after the exchange.

```python
authorization = await client.get_authorization_url(
    redirect_uri="https://yourapp.com/callback",
    context={"user_id": "U123", "tenant_id": "T456"},
)

# On callback, context comes back on the TokenSet.
tokens = await client.exchange_code(
    AuthorizationCallback.from_query(query), browser_token=cookie_browser_token
)
print(tokens.context["user_id"])    # "U123"
print(tokens.context["tenant_id"])  # "T456"

# Provider response extras (e.g. Slack's team_id) are separate.
print(tokens.extras)  # {"team_id": "T123", ...}
```

`TokenSet.extras` holds every field a token response carried that no attribute names. A field whose value is not of the type its attribute states lands there too, and the attribute keeps its default, so `scope`, `refresh_token`, `expires_in` and `expires_at` state nothing, and `token_type` reads `Bearer`, while the value the provider sent sits in the extras. `expires_in` is not coerced, so a numeric string lands there rather than becoming an integer, and `expires_at` then states nothing either, because an expiry is derived only from a lifetime this library read. Treat the extras as sensitive: a credential a provider sent in the wrong shape arrives there, which makes them as sensitive as the token fields the model names.

## Connecting to an MCP server

When the provider is not a known preset but a remote MCP (Model Context Protocol) server, `apron_auth.mcp` discovers its OAuth configuration at runtime (RFC 9728 protected-resource metadata + RFC 8414 authorization-server metadata) and, where the server supports it, registers a client dynamically (RFC 7591). The result folds into the same `ProviderConfig`/`OAuthClient` used everywhere else.

```python
from apron_auth import ClientRegistration, OAuthClient, mcp

# 1. Discover the server's OAuth endpoints.
meta = await mcp.discover("https://mcp.example.com", transport_factory=my_transport_factory)

# 2. Obtain a client identity, in the spec's priority order.
if my_pre_registered_client_id:  # an existing relationship with this server
    registration = ClientRegistration(
        client_id=my_pre_registered_client_id,
        client_secret=my_pre_registered_secret,
    )
elif meta.supports_cimd:  # CIMD — the forward path; you host the metadata document
    registration = ClientRegistration(
        client_id=mcp.cimd_client_id("https://app.example.com/oauth/client-metadata.json")
    )
elif meta.registration_url:  # DCR — deprecated, kept for backward compatibility
    registration = await mcp.register_client(
        meta.registration_url, redirect_uri, transport_factory=my_transport_factory
    )
else:
    raise RuntimeError("server offers no supported client-registration mechanism")

# 3. Build a ProviderConfig and drive the normal authorization-code flow.
config = mcp.to_provider_config(meta, registration, redirect_uri=redirect_uri)
client = OAuthClient(config, transport_factory=my_transport_factory)
url, pending = await client.get_authorization_url()
# Redirect the user to `url`. The callback's response carries the `iss`
# parameter, so the issuer is validated before the code is redeemed:
tokens = await client.exchange_code(
    AuthorizationCallback.from_query(query), pending_state=pending
)
```

The config that `to_provider_config` returns names no built-in provider and allows no provider's identity handler, so `fetch_identity` raises `IdentityNotSupportedError` unless you pass an `identity_handler` to the client. An authorization server on a built-in provider's host gets no handler either, which would otherwise send the MCP server's access token to that provider's API.

A `ProviderConfig` that you build by hand from `discover` output names no provider either, so it gets no built-in handler. Pass a handler for the MCP server's own identity contract. Pass a built-in handler, such as `linear.LinearIdentityHandler()` from `apron_auth.providers`, only when that provider's API accepts the MCP server's tokens.

`ServerMetadata` and `ClientRegistration` refuse a field they do not define, so select the model's fields out of an authorization server's own document rather than validating the whole document. RFC 8414 and RFC 7591 both let a server return members this library does not model. `discover` and `register_client` read a document field by field, so a config built through them is unaffected; the rule applies to a model you build or reload yourself.

Public clients are supported end to end: a server that issues no secret yields `ClientRegistration.client_secret = None`, and `to_provider_config` sets `token_endpoint_auth_method` to `TokenEndpointAuthMethod.NONE`.

When using CIMD, you host the `client-metadata.json` yourself at the `client_id` URL — apron-auth is stateless and does not host it. The document must include `client_id`, `client_name`, and `redirect_uris`. Its `client_id` must equal that URL, and its `redirect_uris` must include the redirect you use in the flow; the authorization server fetches and validates the document. `mcp.cimd_client_id(url)` checks the URL is a well-formed CIMD identifier (`https` scheme, a document path, no userinfo, no fragment, and no `.` or `..` path segment in any form, encoded or not) and raises `ConfigurationError` when it is not; it does not fetch the URL.

Unlike DCR or pre-registered credentials — which are bound to the authorization server that issued them and must be re-registered when that server changes — a CIMD `client_id` is a self-hosted URL, portable across authorization servers with no re-registration.

`discover` refuses authorization server metadata whose `issuer` is not the server the document was fetched from (RFC 8414 section 3.3), records that issuer, and `to_provider_config` carries it onto the `ProviderConfig`. The callback's `iss` parameter (RFC 9207) rides on the `AuthorizationCallback` you pass to `exchange_code`, which validates it against that issuer **before** the code is redeemed, refusing an authorization-server mix-up. When the server advertises `iss` support, `to_provider_config` sets `require_iss`, so a callback that omits `iss` is rejected too. There is nothing to remember per call. A preset that names its provider's issuer, such as Slack's sign-in preset, is held to the same rule; one that names none is unaffected.

The registration's `token_endpoint_auth_method` is a `TokenEndpointAuthMethod` validated out of the registration response. It lets the server's per-client choice (RFC 7591) win over the derivation from the advertised set — for example a server that supports both `client_secret_post` and `client_secret_basic` but registers a given client as `basic`-only. A registration you build yourself states no method, so the method is derived from the client's secret and the server's advertised set.

### SSRF safety

Discovery, registration, the token request, and token revocation all fetch URLs taken from server-supplied metadata. `discover`, `register_client`, and either client each accept a **`transport_factory`** (`Callable[[str], httpx.AsyncBaseTransport]`) so the caller controls the actual outbound connection; the client's factory governs both the token request and revocation. For an **untrusted** `server_url` — for example one a user pasted — supply a transport that resolves DNS once and pins the connection to validated public addresses. The built-in HTTPS-only requirement and non-public-IP-literal block are defense-in-depth; they do **not** stop a hostname that resolves to an internal address. A `url_validator` hook is also accepted for URL-string policy. Whatever it raises rejects that URL, and anything that is not an `apron_auth` error is reported as this phase's error with the hook's exception as the cause, never as its message. A `transport_factory` that raises is reported the same way. Rejecting any URL but the metadata hint ends the operation.

Pass `resource_metadata_url` to `mcp.discover` when a `WWW-Authenticate` challenge named one. Its value is the server's, so a hint that cannot be used loses its turn and the well-known locations are still tried, rather than one bad hint ending discovery or being reported as a fault in your configuration. That holds however the hint proves unusable, including when your own `url_validator` or `transport_factory` refuses it, because the hint is the one URL with a fallback and you can withhold it. Every other URL your hooks refuse ends the operation.

## Verifying workload identity tokens

A workload on Google Cloud, GitHub Actions or Kubernetes can fetch a token its platform signed, naming the workload and an audience it chose. A server that trusts the platform can accept that token in place of a secret the workload would otherwise hold, as the OAuth 2.0 JWT bearer grant does (RFC 7523). `apron_auth.workload` is the server side of that: it checks the token, and the server decides what the identity it names may do.

### What this verifies, and what it leaves to you

apron-auth verifies a credential as the protocol defines it: the signature against the issuer's published keys, then `iss`, `aud`, `exp`, `iat` and `nbf`, then the identity the token names. It decides nothing about what a workload may do, finds no credentials for you, and holds no trust list of its own. The issuers you accept and the audiences you answer to are your configuration, passed in as typed values.

```python
from apron_auth import WorkloadIssuer
from apron_auth.errors import IdentityFetchError, TokenExpiredError, TokenValidationError
from apron_auth.workload import WorkloadTokenVerifier

verifier = WorkloadTokenVerifier(
    [WorkloadIssuer(issuer="https://accounts.google.com")],
    transport_factory=my_transport_factory,
)

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

`verify` is the one-shot for a server whose accepted audience is fixed. It is the two steps below, called one after the other.

### When the accepted audiences come from a lookup

A server that decides its accepted audiences per tenant calls the two steps itself, so the signature is checked before the lookup runs:

```python
# Step one checks the signature and every claim but the audience match.
checked = await verifier.check(token)

# `checked` states only `issuer` and `audiences` — enough to narrow a lookup by a verified value.
accepted = await my_store.audiences_for(checked.issuer, checked.audiences)

# Step two names the workload, and only once an audience you accept is among them.
identity = checked.accept(accepted)
```

`check` offers no identity, so the step that rules out a token minted for another service comes before the step that names its workload, and a lookup written against this shape cannot act on one it has not accepted. That ordering is the interface rather than a boundary Python enforces: a caller that reaches past it, or that calls `check` and ignores `accept`, decides for itself what it trusts.

### Accepting several issuers

Pass one `WorkloadIssuer` per platform you trust. A token is checked against the published keys of the issuer its `iss` names and against no other, so accepting several never lets one of them sign for another. The claim is read before any signature is checked and only selects which keys to use: the signature check and the claim validation that follow both hold the token to the issuer it selected. A token naming an issuer you did not pass is refused before any request is sent. Each issuer keeps its own discovery state, so one that is unreachable refuses only its own tokens.

### Keys, and the audience rule

The issuer's signing keys are found through its OpenID configuration document, of which only `issuer` and `jwks_uri` are read, so an issuer with no authorization endpoint, as most workload issuers are, is discovered too. Set `WorkloadIssuer.jwks_url` to skip discovery. The keys are kept for an hour, and a token no cached key verifies refetches them early, at most once a minute. A token naming a key the key set lacks also has the configuration document read again, at most once a minute, and the key set that document names replaces the one in use once a key of it verifies that token. An issuer that moves its key set while the old one still answers is followed that way, without a restart. Two cases are not: an issuer whose old key set URL stops answering altogether is reported as an outage rather than rediscovered, and a token that arrives while the first one is still proving the move is refused and succeeds on retry. Only public-key algorithms are accepted, and a published RSA key shorter than 2048 bits is skipped, here and in every OpenID sign-in. `iss` must name the issuer exactly, and `sub`, `aud`, `exp` and `iat` are required.

`audience` is required, at both entry points. Pass the audience your server answers to, or several of which the token must name one. One that names nothing — an empty collection, an empty name, or `None` — is a `ConfigurationError`, because it would accept a token minted for any service.

A matching audience proves the token was minted for your server, not that the workload is one you trust: on a shared platform anyone can mint a token for any audience, so any Google Cloud service account or any GitHub repository can present one. Decide what the token may do from its subject and the claims that name its owner. Prefer a platform's immutable identifiers to names that can be reused, such as GitHub's `repository_id` and `repository_owner_id` over a `sub` built from the repository name, which a renamed or recreated repository takes over.

The configuration document and key set URLs are fetched through `transport_factory`, as in [SSRF safety](#ssrf-safety). The issuer is the caller's, but the key set URL comes from the issuer's document.

An issuer on the loopback interface may use `http` with no opt-in, because a request to it reaches no network, and so may a key set URL discovered from it. For a development issuer that is not loopback, build it with `WorkloadIssuer.unsafe.allow_plain_http("issuer", "jwks_url", issuer="http://keycloak:8080")`: the first name covers the issuer and its configuration document, the second covers the key set URL that document names. A waiver has to be stated in code, cannot arrive as data, and is for local development only.

## Provider presets

Every preset sets `ProviderConfig.provider` to its `Provider` member, which carries the provider's `disconnect_fully_revokes` value and scope separator. A hand-built, generic OpenID, or MCP config leaves it `None`.

| Provider   | Preset                   | Revocation             | `disconnect_fully_revokes` |
|------------|--------------------------|------------------------|----------------------------|
| Google     | `google.preset(...)`     | POST with query param  | `True`                     |
| GitHub     | `github.preset(...)`     | DELETE with Basic auth | `True`                     |
| Slack      | `slack.preset(...)`, `slack.sign_in_preset(...)` | POST with Bearer header | `False`       |
| Notion     | `notion.preset(...)`     | POST with Basic auth   | `False`                    |
| Microsoft  | `microsoft.preset(...)`  | —                      | `False`                    |
| Atlassian  | `atlassian.preset(...)`  | RFC 7009 POST          | `False`                    |
| Linear     | `linear.preset(...)`     | RFC 7009 POST          | `False`                    |
| Salesforce | `salesforce.preset(...)` | RFC 7009 POST          | `False`                    |
| Typeform   | `typeform.preset(...)`   | —                      | `False`                    |
| HubSpot    | `hubspot.preset(...)`    | DELETE refresh-token   | `False`                    |
| Any OpenID | `oidc.preset(...)`       | RFC 7009 POST, if advertised | `False`              |

### Slack installs and sign-ins are separate flows

Slack serves installing an app in a workspace and signing a person in from different endpoints, and states that each set of scopes must be requested in its own OAuth flow. `slack.preset(...)` configures the install on `oauth/v2`, and `slack.sign_in_preset(...)` configures Sign in with Slack on Slack's OpenID endpoints.

Only Slack's OpenID token endpoint returns an ID token, so only the sign-in flow can carry the nonce the authorization request sent. `slack.sign_in_preset(...)` always requests `openid` and names Slack's issuer, so an ID token naming another issuer or another audience, or carrying no nonce, is refused. It accepts `email` and `profile` beside `openid` and refuses any other scope, because Slack grants those three from these endpoints. `slack.preset(...)` refuses `openid` in `scopes` and in `user_scopes`, because its token endpoint returns no ID token and nothing would check the nonce.

Neither preset accepts a `scope` key in `extra_params`, because each builds that parameter from the scopes it was given and an extra parameter of the same name would replace it. A configuration whose token endpoint and requested scopes name different flows is refused by `fetch_identity` with a `ConfigurationError`, so a config built by hand cannot take the person-identity path without the checks that make it trustworthy. That refusal reads the `scope` and `user_scope` parameters the authorization request will actually send, which is the first of the authorization URL's own query, the configured scopes and `extra_params` to set each one.

Run the two flows separately. The install yields a bot token for workspace work, and the sign-in yields a user token that identifies the person.

An install that asks for user scopes as well as bot scopes receives two tokens. The bot token is `token_set.access_token`, and the token for the person who installed the app is `token_set.user_token`. A response that nests a second token has it read onto that field whether or not the config names a provider, because `provider` is a field the caller chooses and the person's token is no less live without it.

```python
config = slack.preset(
    client_id="...",
    client_secret="...",
    scopes=["channels:read"],
    user_scopes=["chat:write"],
    redirect_uri="https://app.example.com/callback",
)
client = OAuthClient(config=config)
url, pending_state = await client.get_authorization_url()
tokens = await client.exchange_code(
    AuthorizationCallback.from_query(query), pending_state=pending_state
)
```

Each token is revoked on its own, so disconnecting the install revokes both, and the refresh token beside each one where the install rotates its tokens:

```python
await client.revoke_token(SecretToken(tokens.access_token))
if tokens.refresh_token is not None:
    await client.revoke_token(SecretToken(tokens.refresh_token))
if tokens.user_token is not None:
    await client.revoke_token(SecretToken(tokens.user_token.access_token))
    if tokens.user_token.refresh_token is not None:
        await client.revoke_token(SecretToken(tokens.user_token.refresh_token))
```

`OAuthClient.refresh_token` refreshes the token in `token_set.access_token`, so it cannot refresh the user token: Slack returns a refreshed user token nested as well, and a response carrying no token at the top level is refused. Passing `token_set.user_token.refresh_token` to it spends that token at Slack and then fails, though the refusal revokes whatever the response issued, so nothing is left valid and unreachable. Refresh a rotating user token with Slack's own endpoint for now.

Revoking the bot token alone leaves the person's token valid. Slack does not document whether revoking an access token affects the refresh token paired with it, so revoke every refresh token you hold and treat each revocation as best effort. Slack's own `apps.uninstall` removes every token of an installation, which no single revocation here promises.

`slack.preset(...)` refuses an install that asks for user scopes alone, because Slack then returns no token for the app itself and a token response carrying no access token is refused. Sign a person in with `slack.sign_in_preset(...)` instead, whose token endpoint returns the person's token as `token_set.access_token`.

## Scope reduction tiers

Some providers' revocation endpoints fully remove the user's portal-level OAuth grant; others only invalidate the current token while the grant lingers. apron-auth surfaces this difference as `ProviderConfig.disconnect_fully_revokes` so consumers can offer the right scope-reduction UX without rebuilding the per-provider truth table inline.

| Tier | Meaning                                                                                                             | When                                |
|------|---------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| 1    | Automatic scope reduction: revoke + re-auth presents a fresh consent screen, narrower scopes take effect.           | `disconnect_fully_revokes is True`  |
| 3    | Manual via provider settings: deep-link the user to the provider's app management page; revoke alone is not enough. | `disconnect_fully_revokes is False` |

```python
from apron_auth.providers import google, hubspot

google_config = google.preset(...)
hubspot_config = hubspot.preset(...)

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

A response that states a `Retry-After` is read as temporary whatever its status is, on every request this library sends. A status alone cannot tell a throttle from a refusal where a server answers both with one status, and GitHub answers a secondary rate limit with 403. A redirect is the one exception: this library follows none, so no wait makes an endpoint stop redirecting. A header that states nothing states no condition.

| `kind`          | Meaning                                                                                  | `retryable` |
|-----------------|------------------------------------------------------------------------------------------|-------------|
| `CONFIGURATION` | Your configuration or an argument cannot work.                                           | no          |
| `REFUSED`       | apron-auth refused what the other side sent: a token, a document or a response that does not validate. | no |
| `REJECTED`      | The other side refused the request as sent: a client error status or an OAuth error code. | no          |
| `SERVER_ERROR`  | The other side answered with a server error or a rate limit, or asked to be called again later. | yes |
| `TIMEOUT`       | The request ran out of time.                                                             | yes         |
| `UNEXPECTED`    | An error apron-auth does not classify, such as a fault in a handler you supplied.        | no          |
| `UNREACHABLE`   | The other side could not be reached.                                                     | yes         |

| Exception                      | When it's raised                                                                                                |
|--------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `AuthorizationResponseError`   | The authorization response cannot be acted on: the server refused the request and said why, or answered with neither a code nor an error, or with both, or stated one parameter twice. Carries `error_code` where the server named one. Nothing was redeemed, so nothing needs revoking. `AuthorizationCallback.from_query` raises the twice-stated case, so wrap that call too. |
| `TokenExchangeError`           | Code exchange failed: the token endpoint refused the code, or its response was refused. Carries `error_code`. Never `retryable`: a code is single-use, so start a new authorization. |
| `IdTokenValidationError`       | The ID token is unreadable, names another audience, authorized party or issuer, or has expired. Subclass of `TokenExchangeError`. |
| `NonceValidationError`         | The response has no ID token, or it lacks the nonce. Subclass of `IdTokenValidationError`. |
| `TokenRefreshError`            | Refresh failed, or its response carried an ID token that was not issued to your client. `retryable` tells an outage from a dead grant, and `error_code` tells a dead grant (`invalid_grant`) from a client fault. |
| `RevocationError`              | The revocation request could not be sent, the provider refused it, or the provider answered something that states no outcome. `retryable` tells a rate limit or an outage from a refusal, so a token worth retrying is not abandoned. |
| `StateError`                   | OAuth state was missing, invalid, expired, already used, did not match the pending state, did not come from the browser that started the flow, or states a nonce that contradicts the scope its request asked for. |
| `ConfigurationError`           | Something's wrong with the provider config (e.g. missing `redirect_uri`), or an argument you passed cannot work — such as an MCP server, registration or CIMD client-identifier URL this library refuses, a `TokenSet` reloaded from storage passed to `fetch_identity`, or a configuration an identity or revocation handler refuses. |
| `IdentityNotSupportedError`    | No identity handler exists for this provider configuration. Subclass of `ConfigurationError`.                  |
| `McpDiscoveryError`            | MCP OAuth metadata discovery failed — a blocked or rejected URL the server's metadata declares, or unreachable or malformed server metadata. When no candidate URL yields a document, the message names what the candidates showed — the document could not be fetched, is not published, or is not a JSON object — and `kind` says whether a retry may pass. A URL you passed raises `ConfigurationError` instead, except the `resource_metadata_url` hint, whose value is the server's and which loses only its turn. |
| `McpRegistrationError`         | MCP OAuth dynamic client registration (RFC 7591) failed at the server.                                          |
| `OidcDiscoveryError`           | Reading an OpenID provider's configuration document failed, or the document named a different issuer.           |
| `IdentityFetchError`           | Fetching the user's identity failed. `kind` tells an outage from a refusal, and `error_code` carries the code the provider stated where it stated one as a lowercase identifier. |
| `IdentityScopeNotGrantedError` | The token lacks a scope the identity endpoint needs. Subclass of `IdentityFetchError`.                          |
| `TokenValidationError`         | An ID token or workload token was refused. `reason` says why: `audience`, `claims`, `expired`, `malformed`, `signature`, `unknown_issuer`, `unknown_key` or `unsupported`. Subclass of `IdentityFetchError`, so catch it first. |
| `TokenExpiredError`            | An ID token or workload token verified but has expired. Subclass of `TokenValidationError`.                     |

`TokenExchangeError` and `TokenRefreshError` share the `TokenEndpointError` base, which is where their `error_code` lives. `AuthorizationResponseError` and `IdentityFetchError` carry one of their own, under the same rule.

No message holds text a provider wrote. A provider states the reason for a failure in a field whose length and content are its own to choose, so a message names the request that failed and the condition this library read, and the provider's own value reaches you through `error_code` where it takes the shape a code takes. A failure with several reasons, as a GraphQL response states, reports how many rather than any of their text.

### What an error reporter can capture

An error reporter such as Sentry records the local variables of every frame a traceback holds, and Sentry does so by default (`include_local_variables=True`). A credential held in one of those is recorded, which no rule about an error's message or its exception chain reaches.

On the revocation and identity paths, including ID token verification, this library holds every credential it passes between its own frames in a wrapper whose `repr` states a row of asterisks, and every token it hands to handler code in a `SecretToken`, which also refuses to state itself as text. The one value there that cannot be wrapped, a built revocation request whose provider may state the token anywhere in it including the request line, names only its method, its provider label and the host it would reach. Each of those paths also raises errors that attach nothing they caught, so a traceback holds no frame of the HTTP client, its transport or the token parser. A reporter that captures a frame of either path therefore records no token and no client secret. `make test` holds that rule for every bundled handler by walking a failed request's traceback and asserting all of it: the credential reached the request, the error attaches nothing, every frame but the test's own belongs to this library, and none of them states the credential.

Three limits are worth knowing, and the third is the one to act on.

The guarantee is about what a value states, so a reporter that walks object attributes recursively rather than reading a `repr` can still reach the string inside a wrapper.

Your own frames are yours. A token you read off a `TokenSet` is a plain string in your code, as is the value you pass to `SecretToken(...)` and anything you unwrap in a handler of your own.

**The token-endpoint paths are not covered.** `exchange_code` and `refresh_token` take the authorization code, the PKCE verifier and the refresh token as plain strings, and each raises from its own frames, so a captured traceback of a failed exchange or refresh states them. Measured against a refused exchange, the code appears in five frame locals and the verifier in five; against a refused refresh, the refresh token appears in two. Covering those means wrapping the token fields of `TokenSet` itself, which is not done.

So for code that handles tokens, turn local-variable capture off or scrub it, with Sentry's `include_local_variables=False` or a `before_send` hook. The wrapping above reduces what a capture reveals; it does not make the capture safe.

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
| `apron_auth.mcp`                 | What each discovery candidate answered, and a metadata hint that could not be used (DEBUG). |
| `apron_auth.models`              | Plain `http` accepted for a model's named URL fields.        |
| `apron_auth.providers._jwks`     | Signing key set refresh failures and skipped keys.           |
| `apron_auth.providers.atlassian` | Person-level profile withheld after a User Identity API failure. |
| `apron_auth.providers.github`    | Grant revocation the provider did not confirm.               |
| `apron_auth.providers.microsoft` | Withheld tenancy assertions.                                 |
| `apron_auth.providers.oidc`      | Insecure `http` allowed by opt-in; no PKCE advertised; userinfo failure degraded; a refused discovery redirect (DEBUG). |
| `apron_auth.stores`              | Expired OAuth state discarded on lookup, and how many the pruning scan discarded. |
| `apron_auth.workload`            | A workload issuer's signing keys now read from another URL, and a move that did not verify. |

Three levels are used. `WARNING` marks a capability that degraded without
raising — a revocation the provider would not confirm, or a
domain-ownership assertion withheld because a directory lookup failed.
Both deserve an operator's attention precisely because they do not
surface as exceptions: the call returns, and the effect is silent. A
withheld assertion in particular makes domain-gated access refuse.
`INFO` records a change this library made for itself that an operator may
want to see, such as a workload issuer's signing keys being read from
another URL. `DEBUG` carries diagnostic detail: expired state, what each
discovery candidate answered, and provider response parsing that is useful
when a response format changes.

There is no `logger` parameter to inject. The logging hierarchy is the
injection point: because every module logs to its own `__name__`,
configuring `apron_auth` reaches all of them, and adapters, filters, and
`contextvars` compose with it in the usual way.

### What is never logged

Access tokens, refresh tokens, client secrets, OAuth state, and ID-token payload bytes are never written to logs at any level. Exception *values* are not logged either — in their place goes whichever non-sensitive primitive actually carries diagnostic signal, such as an HTTP status code or an exception class name. Where no such primitive is at hand, the line is fixed text only. A raised exception's rendering can embed the request that carried a credential, and for some providers a token travels in the URL path, so the exception value is not safe to emit generically.

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
