# authbridge

[![ci](https://github.com/AhogeYI/pocketbase-authbridge/actions/workflows/ci.yml/badge.svg)](https://github.com/AhogeYI/pocketbase-authbridge/actions/workflows/ci.yml)

Turn [PocketBase](https://pocketbase.io) into the identity issuer for your standalone services, the way Supabase does it: PocketBase mints **short-lived HS256 "service tokens"**, and every resource server verifies them **offline** with the shared secret — zero per-request call back to the auth plane.

```
client ──login──► PocketBase ──auth response──► { token, meta.serviceToken }
client ──Bearer serviceToken──► your services ──verify offline (authtoken pkg)
```

Two consumers, one repo, two modules:

| Module | Who imports it | What it gives them |
|---|---|---|
| `github.com/ahogeyi/authbridge` (root) | your PocketBase binary | the issuer: mints tokens on every login/refresh + an explicit mint endpoint |
| `github.com/ahogeyi/authbridge/authtoken` | your resource services | the verifier: sign/parse with **no PocketBase dependency at all** |

The verifier being dependency-light is deliberate: services add the token check without dragging the identity plane into their module graph. It is the wire contract between the two sides.

## Issuer side (PocketBase extension)

```go
import (
    authbridge "github.com/ahogeyi/authbridge"
    "github.com/pocketbase/pocketbase"
)

func main() {
    app := pocketbase.New()
    authbridge.Register(app)   // before serve
    if err := app.Start(); err != nil { log.Fatal(err) }
}
```

Plain `Register(app core.App)` form — PocketBase's sanctioned extension pattern (discussion [#7612](https://github.com/pocketbase/pocketbase/discussions/7612)); versioned as an ordinary `go.mod` dependency. A runnable skeleton lives in [`example/main.go`](example/main.go).

**Surfaces:**

- every successful authentication of an application user carries a fresh service token in the auth response: `meta.serviceToken` / `meta.serviceTokenType` / `meta.serviceTokenExpiresAt` — login, refresh, OAuth, custom auth flows all inherit it, so a client's existing "401 → refresh → retry" loop needs **zero extra calls** to keep the token fresh;
- explicit mint: `POST /api/authbridge/v1/token` (PocketBase auth required) → `{"token","tokenType","expiresAt"}`.

**Configuration** (env):

| Var | Default | Meaning |
|---|---|---|
| `AUTHBRIDGE_SHARED_SECRET` | — | HS256 signing secret, **≥32 chars**; the same value every verifying service holds. **Empty = the extension stays dark** (fail-closed: no routes, no hook). |
| `AUTHBRIDGE_TOKEN_TTL` | `1h` | token lifetime (Go duration). Offline verification has no revocation — keep the window short, refresh is free. |
| `AUTHBRIDGE_ISSUER` | `authbridge` | issuer claim. |

Superusers never receive service tokens: the bridge speaks for application users, not for the admin plane.

## Verifier side (resource services)

```go
import "github.com/ahogeyi/authbridge/authtoken"

func authenticate(r *http.Request) (userID string, ok bool) {
    raw := strings.TrimSpace(r.Header.Get("Authorization"))
    token, _ := strings.CutPrefix(raw, "Bearer ")
    claims, err := authtoken.Parse(token, []byte(sharedSecret), "authbridge")
    if err != nil {
        return "", false // answer 401: a refreshable user credential failed
    }
    return claims.Subject, true
}
```

Token shape: standard JWT, registered claims only — `iss` / `sub` (the PocketBase user id) / `iat` / `exp` / `jti` (random, the hook for a future denylist). No permissions, no PII: tokens end up in logs. `Parse` rejects wrong-issuer, expired, tampered, `alg=none`, and weak-secret configurations; `Sign` refuses empty identity.

**Why symmetric (HS256)?** Same trade-off as Supabase's default: one shared secret, trivial deployment. The cost: every verifier holds a signing key, so compromise of any service allows forgery. Roadmap: an asymmetric mode (RS256 + JWKS endpoint) where verifiers only ever hold public keys — the verifier API is already shaped for it.

## Status

Running in production: three standalone services authenticate direct client requests with these tokens, dual-track alongside a legacy gateway path.

## Versioning & PocketBase compatibility

PocketBase is pre-1.0 and its minors occasionally break Go extensions (the
v0.22 → v0.23 rewrite is the canonical example). Releases of this extension
therefore follow PocketBase:

- Every release **pins and is verified against exactly one PocketBase
  version** — the one in its `go.mod`. That pin is the compatibility statement.
- The extension's own tags are plain semver (`vX.Y.Z`), as Go modules require:
  - **minor** (`v0.N.0`) — a newly verified PocketBase line (the common case
    whenever PocketBase ships a minor worth tracking);
  - **patch** (`v0.N.M`) — this extension's own fixes, PocketBase pin unchanged;
  - **major** — a break in this extension's own public API.
- The current stable PocketBase line is tracked; the previous line gets patch
  backports on demand (open an issue).

| Extension | PocketBase | Notes |
|---|---|---|
| v0.1.x | v0.40.4 | initial cut |

## License

Apache-2.0 — see [LICENSE](LICENSE). Third-party components: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
