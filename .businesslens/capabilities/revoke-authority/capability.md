---
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/localauthority/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server localauthority
---

# Revoke an authority

Remove a tainted X.509, JWT or upstream authority from the bundle so nothing
it signed is trusted any more, and propagate the removal to agents and
federated trust domains.
