---
availability:
  - place: envoy-sds
references:
  - kind: code
    role: implementation
    target: pkg/agent/endpoints/sdsv3/handler.go
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: Envoy SDS Support
---

# Fetch secrets

An Envoy proxy receives TLS certificates and validation contexts by resource
name and keeps receiving updates as SVIDs and bundles rotate. A certificate is
named by SPIFFE ID or by the default name; a validation context by trust
domain, by the name for the agent's own trust domain, or by the name for all
trust domains.
