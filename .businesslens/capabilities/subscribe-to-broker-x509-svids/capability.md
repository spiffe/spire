---
availability:
  - place: broker-api
references:
  - kind: code
    role: implementation
    target: pkg/agent/broker/api/service.go
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: SPIFFE Broker API
---

# Subscribe to brokered X.509-SVIDs

A broker receives the X.509-SVIDs, with keys, of a workload it names by
reference, after the agent attests that reference, and keeps receiving them as
they rotate.
