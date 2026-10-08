---
appliesTo:
  - type: entity
    id: x509-svid
    effect: reads
    contexts:
      - place: delegated-identity-api
permits:
  - actors:
      - authorized-delegate
references:
  - kind: code
    role: implementation
    target: pkg/agent/api/delegatedidentity/v1/service.go
---

# Only authorized delegates receive X.509-SVIDs through the Delegated Identity API

The caller must attest to a SPIFFE ID listed in the agent's authorized
delegates; it is checked again on every update of the stream.
