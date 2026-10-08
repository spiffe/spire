---
kind: unattended
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "An agent's SVID expired longer ago than the configured pruning age"
    kind: condition
    unattended: true
    entities:
      - {entity: agent, effect: reads, facts: [Expiration time, Can re-attest]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product removes the expired agent
    kind: product
    entities:
      - {entity: agent, effect: removes, from: Attested}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Expired agents are pruned

## Trigger

About every hour, when the server's `prune_attested_nodes_expired_for` setting
is configured.

## Outcome

Agents whose SVID expired longer ago than the configured time are removed;
banned agents are kept, and agents that cannot re-attest are removed only when
`prune_tofu_nodes` is set.
