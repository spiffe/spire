---
domain: federation
references:
  - kind: code
    role: implementation
    target: pkg/server/api/trustdomain.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: Federation configuration
---

# https_spiffe federation relationship

A dynamic federation relationship with a foreign trust domain whose bundle
endpoint authenticates with SPIFFE authentication (the `https_spiffe` bundle
endpoint profile), presenting an X.509-SVID the server verifies with the
foreign bundle it already holds. Relationships in the server's configuration
file are static, are not part of this record, and take precedence for the same
trust domain.

## Information kept

- **Trust domain** — the foreign trust domain
- **Bundle endpoint URL** — the HTTPS address of the foreign SPIFFE bundle endpoint
- **Endpoint SPIFFE ID** — the SPIFFE ID the bundle endpoint must present
