---
availability:
  - place: delegated-identity-api
references:
  - kind: code
    role: implementation
    target: pkg/agent/api/delegatedidentity/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: Delegated Identity API
---

# Subscribe to delegated X.509-SVIDs

An authorized delegate receives the X.509-SVIDs, with keys, of a process it
identifies either by selectors it attested itself or by a process ID the agent
attests, with the federated bundles they need, and keeps receiving them as
they rotate.
