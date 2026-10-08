---
references:
  - kind: code
    role: implementation
    target: pkg/server/api/svid/v1/service.go
  - kind: code
    role: implementation
    target: pkg/agent/manager/manager.go
---

# X.509-SVID

An X.509 certificate carrying a SPIFFE ID, with its private key, that software
uses for mTLS. Agents keep the X.509-SVIDs of their workloads and replace them
before they expire.

## Information kept

- **SPIFFE ID** — the identity the certificate carries
- **Certificate chain** — the certificate and any intermediates up to an X.509 authority
- **Private key** — the key matching the certificate
- **DNS names** — DNS names included from the registration entry or request
- **Expires at** — when the certificate stops being valid
- **Hint** — the registration entry's hint
