---
relations:
  - entity: registration-entry
    verb: names
    cardinality: one-to-one
references:
  - kind: code
    role: implementation
    target: "pkg/server/api/agent/v1/service.go#CreateJoinToken"
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server token generate
---

# Join token

A single-use secret an Operator gives one agent to attest its node with when
no platform evidence is available. Presenting it uses it up, even after it has
expired.

## Information kept

- **Token** — the secret value the agent presents
- **Expires at** — after this time attesting with it is refused
