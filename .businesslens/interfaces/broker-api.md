---
type: api
actors:
  - broker
references:
  - kind: code
    role: implementation
    target: pkg/agent/broker/api/service.go
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: SPIFFE Broker API
---

# SPIFFE Broker API

The SPIFFE Broker API the agent serves on its own mutually authenticated
socket or TCP address, through which an authorized broker obtains identities
and bundles for a workload it names by reference. It exists only while the
agent's experimental `broker` section is configured.
