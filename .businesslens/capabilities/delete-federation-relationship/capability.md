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
    target: cmd/spire-server/cli/federation/delete.go
---

# Delete a federation relationship

Stop refreshing a foreign trust domain's bundle. The bundle already held stays
until it is deleted.
