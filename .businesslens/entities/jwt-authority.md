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

# JWT authority

A JWT signing key the server holds for its own trust domain. Its public key is
published in the bundle; the server keeps a current and a next authority. It
exists only while JWT-SVIDs are enabled.

## Information kept

- **Authority ID** — the key ID of the signing key
- **Expires at** — when the signing key expires

## States

### Prepared

Generated and published in the bundle, ready to be activated.

### Active

Signs every new JWT-SVID the server issues.

### Old

Replaced by a newer authority; it stays in the bundle so existing JWT-SVIDs
still verify.

### Tainted

Marked in the bundle as no longer trusted for signing: agents and downstream
servers replace what it signed.
