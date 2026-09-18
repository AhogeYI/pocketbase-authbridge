# Contributing

```bash
cd authtoken && go vet ./... && go test ./...   # verifier module
cd .. && go vet ./... && go test ./...            # extension module
# CI additionally runs everything under -race (needs cgo locally)
go build -o /dev/null ./example                        # integration example must compile
```

## Red lines

- **Fail-closed**: with `AUTHBRIDGE_SHARED_SECRET` unset or too short the
  extension stays unmounted — no change may leak the minting path on a
  keyless deployment.
- **Superusers never get service tokens**: the bridge speaks for application
  users only.
- **Identity-only claims** (iss/sub/iat/exp/jti): no permissions, no PII —
  tokens end up in logs.
- `authtoken` must keep zero PocketBase dependencies, and the extension must
  not leak PB types into `authtoken`'s API (CI enforces the first half).
- Claim-set/verification changes must stay backward-compatible with issued
  tokens, or bump the major version with a migration note.

## Welcome shapes

- Asymmetric mode (RS256 + JWKS endpoint; verifiers hold public keys only);
- a `jti` denylist hook;
- an `aud` claim for multi-audience deployments.

## Commits

One logical step per commit, `feat:` / `fix:` / `docs:` / `chore:` / `security:`;
sign your commits (`git commit -s`, DCO).

## PocketBase upgrades

1. Bump the pin in the root `go.mod` (`authtoken` has no PocketBase dependency).
2. `go vet ./... && go test ./...` in both modules — fix whatever broke.
3. Bump the extension's **minor**, add a row to the compatibility table in
   the README, and name both versions (extension + PocketBase) in the release.
