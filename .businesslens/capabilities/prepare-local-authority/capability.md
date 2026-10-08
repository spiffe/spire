---
domain: local-authority
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
  - kind: code
    role: implementation
    target: pkg/server/ca/manager/manager.go
  - kind: code
    role: implementation
    target: pkg/server/ca/rotator/rotator.go
---

# Prepare a local authority

Generate a new X.509 or JWT authority and publish it in the bundle ahead of
activation, so that trust in it spreads before it signs anything. The server
also prepares the next authority on its own.
