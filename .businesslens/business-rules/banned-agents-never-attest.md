---
appliesTo:
  - type: entity
    id: agent
    effect: changes
    from: Banned
permits: []
references:
  - kind: code
    role: implementation
    target: "pkg/common/nodeutil/node.go#IsAgentBanned"
---

# A banned agent never attests or renews again

Nothing moves an agent out of Banned; only evicting its record lets the node
attest again.
