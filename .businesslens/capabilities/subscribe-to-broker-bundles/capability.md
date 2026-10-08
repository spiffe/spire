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

# Subscribe to brokered bundles

A broker receives every X.509 or JWT bundle the agent holds for a workload it
names by reference, and each change to them.
