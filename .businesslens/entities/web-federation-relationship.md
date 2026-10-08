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

# https_web federation relationship

A dynamic federation relationship with a foreign trust domain whose bundle
endpoint authenticates with Web PKI (the `https_web` bundle endpoint profile).
Relationships in the server's configuration file are static, are not part of
this record, and take precedence for the same trust domain.

## Information kept

- **Trust domain** — the foreign trust domain
- **Bundle endpoint URL** — the HTTPS address of the foreign SPIFFE bundle endpoint
