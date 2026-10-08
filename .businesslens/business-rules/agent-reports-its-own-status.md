---
appliesTo:
  - type: entity
    id: agent
    effect: changes
    facts:
      - Agent version
permits:
  - self: true
references:
  - kind: code
    role: implementation
    target: pkg/server/authpolicy/policy_data.json
---

# Only the agent itself reports its version

The version on an agent's record is set only by that agent posting its status.
