---
domain: federation
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/trustdomain/v1/service.go
  - kind: code
    role: implementation
    target: pkg/server/api/trustdomain.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: Federation configuration
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/federation/update.go
---

# Edit a federation relationship

Change the bundle endpoint, the profile that authenticates it, or the bundle
of an existing dynamic federation relationship.
