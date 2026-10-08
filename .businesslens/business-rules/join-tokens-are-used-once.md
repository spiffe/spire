---
appliesTo:
  - type: entity
    id: join-token
    effect: removes
permits:
  - actors:
      - agent
references:
  - kind: code
    role: implementation
    target: "pkg/server/api/agent/v1/service.go#AttestAgent"
---

# Only an attesting agent uses up a join token

A join token is removed when an agent presents it to attest, whether the
attestation succeeds or the token has expired, so no token attests twice.
