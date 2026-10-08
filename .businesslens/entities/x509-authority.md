---
domain: local-authority
references:
  - kind: code
    role: implementation
    target: pkg/server/api/localauthority/v1/service.go
  - kind: code
    role: implementation
    target: pkg/server/ca/manager/manager.go
---

# X.509 authority

A signing CA the server holds for its own trust domain, either self-signed or
signed by an upstream authority. Its CA certificate is published in the
bundle; the server keeps a current and a next authority.

## Information kept

- **Authority ID** — the subject key ID of the CA certificate
- **Expires at** — when the CA certificate expires
- **Upstream authority subject key ID** — the upstream authority that signed it, if any

## States

### Prepared

Generated and published in the bundle, ready to be activated.

### Active

Signs every new X.509-SVID the server issues.

### Old

Replaced by a newer authority; it stays in the bundle so existing X.509-SVIDs
still verify.

### Tainted

Marked in the bundle as no longer trusted for signing: agents and downstream
servers replace what it signed.
