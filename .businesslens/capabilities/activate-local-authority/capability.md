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

# Activate a local authority

Make the prepared X.509 or JWT authority the one that signs from now on; the
previously active authority becomes old. The server also activates on its own.
