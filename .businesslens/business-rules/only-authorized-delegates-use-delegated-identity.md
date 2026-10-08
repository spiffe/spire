---
appliesTo:
  - type: context
    context:
      place: delegated-identity-api
references:
  - kind: code
    role: implementation
    target: pkg/agent/api/delegatedidentity/v1/service.go
---

# Only authorized delegates obtain identities for other processes

The Delegated Identity API serves only callers holding a SPIFFE ID listed in
the agent's authorized delegates, and never hands out admin or downstream
identities. An authorized delegate can impersonate any process it obtains
identities for.
