# Third-party notices

pocketbase-authbridge is distributed under [Apache-2.0](LICENSE). This
repository ships two modules; the components involved in their builds
(`go.mod` requirements) are:

| Component | License | Used by |
| --- | --- | --- |
| [PocketBase](https://github.com/pocketbase/pocketbase) v0.40.4 | MIT | Root module (issuer extension) — host framework |
| [golang-jwt/jwt](https://github.com/golang-jwt/jwt) v5 | MIT | `authtoken` module — JWT signing/verification |

The `authtoken` module deliberately depends on golang-jwt only (zero
PocketBase dependencies), so resource services can import it without pulling
the identity plane into their module graph. The authoritative transitive list
for any produced binary is the consumer's own `go.mod` / `go.sum`.
