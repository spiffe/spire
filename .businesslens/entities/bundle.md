---
relations:
  - entity: x509-authority
    verb: contains
    cardinality: one-to-many
  - entity: jwt-authority
    verb: contains
    cardinality: one-to-many
  - entity: upstream-authority
    verb: contains
    cardinality: one-to-many
references:
  - kind: code
    role: implementation
    target: pkg/server/api/bundle/v1/service.go
  - kind: doc
    role: context
    target: doc/spire_server.md
    title: spire-server bundle
---

# Bundle

The trust bundle of one trust domain: the X.509 and JWT authorities that
software trusts when it verifies identities from that domain. The server keeps
the bundle of its own trust domain and a federated bundle for each foreign
trust domain it trusts.

## Information kept

- **Trust domain** — the trust domain the bundle belongs to
- **X.509 authorities** — CA certificates that verify X.509-SVIDs, each marked when tainted
- **JWT authorities** — public keys that verify JWT-SVIDs, each with its key ID and expiry, marked when tainted
- **Refresh hint** — how often consumers should fetch the bundle again
- **Sequence number** — the bundle's version; the server raises it each time it changes its own bundle
