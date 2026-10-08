---
appliesTo:
  - type: entity
    id: agent
    effect: changes
    to: Attested
permits:
  - self: true
references:
  - kind: code
    role: implementation
    target: "pkg/server/api/agent/v1/service.go#RenewAgent"
---

# Only the agent itself renews or re-attests its own SVID

An attested agent obtains a new agent SVID only for itself, authenticating
with its current SVID or with fresh evidence.
