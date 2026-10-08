---
availability:
  - place: workload-api
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/workload/handler.go
  - kind: code
    role: implementation
    target: pkg/agent/manager/manager.go
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: allow_unauthenticated_verifiers
---

# Fetch bundles

A workload receives the X.509 or JWT bundles it should trust, its own trust
domain's and those of the trust domains its entries federate with, and keeps
receiving them as they change.
