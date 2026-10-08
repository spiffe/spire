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

# Subscribe to delegated bundles

An authorized delegate receives every X.509 or JWT bundle the agent holds, and
each change to them.
