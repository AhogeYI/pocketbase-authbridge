## What

<!-- One paragraph: what this PR does and why. -->

## Verification

- [ ] `go vet ./... && go test ./...` green (root AND authtoken; CI adds `-race`)
- [ ] `authtoken` still has zero PocketBase dependencies (`grep pocketbase authtoken/go.mod` empty)
- [ ] claim-set changes stay identity-only (iss/sub/iat/exp/jti) or bump the major version

## Refs

<!-- Issue numbers or discussion links. -->
