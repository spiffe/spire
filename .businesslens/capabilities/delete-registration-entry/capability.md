---
domain: registration-entries
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/entry/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server entry
  - kind: code
    role: implementation
    target: pkg/server/registration/manager.go
---

# Delete a registration entry

Remove a registration entry so no agent issues its identity any more. The
server also removes entries on its own once their expiry has passed.
