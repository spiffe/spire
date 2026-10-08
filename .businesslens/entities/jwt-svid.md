---
references:
  - kind: code
    role: implementation
    target: pkg/server/api/svid/v1/service.go
  - kind: code
    role: implementation
    target: pkg/agent/manager/manager.go
---

# JWT-SVID

A signed JWT carrying a SPIFFE ID for one or more audiences, used where TLS
does not reach. Agents reuse an unexpired JWT-SVID for the same audiences
unless its registration entry asks for a unique token ID.

## Information kept

- **SPIFFE ID** — the identity in the subject claim
- **Token** — the signed JWT
- **Audience** — who the token is for
- **Expires at** — when the token stops being valid
- **Hint** — the registration entry's hint
