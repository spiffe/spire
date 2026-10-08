---
references:
  - kind: code
    role: implementation
    target: pkg/server/api/localauthority/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server upstreamauthority
---

# Upstream authority

An X.509 CA outside SPIRE, reached through an upstream authority plugin, whose
certificate in the bundle signed the server's X.509 authorities. It exists
only while the server is configured with an upstream authority.

## Information kept

- **Subject key ID** — identifies the upstream CA certificate in the bundle

## States

### Trusted

Its certificate is in the bundle and verifies the authorities it signed.

### Tainted

Marked in the bundle as no longer trusted for signing: the authorities it
signed are rotated away from.
