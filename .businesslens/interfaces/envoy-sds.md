---
type: api
actors:
  - workload
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/sdsv3/handler.go
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: Envoy SDS Support
---

# Envoy SDS

The Envoy Secret Discovery Service (SDS v3) the agent serves beside the
Workload API, through which Envoy proxies receive TLS certificates and
validation contexts and have them replaced as they rotate.
