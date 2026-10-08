---
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/svid/v1/service.go
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/x509/mint.go
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/jwt/mint.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server x509 mint and jwt mint
---

# Mint an SVID

Issue an X.509-SVID or a JWT-SVID for any SPIFFE ID in the trust domain
directly, without a registration entry or attestation.
