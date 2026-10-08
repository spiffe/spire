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

# Fetch a brokered JWT-SVID

A broker receives JWT-SVIDs for the audiences it names on behalf of a workload
it names by reference.
