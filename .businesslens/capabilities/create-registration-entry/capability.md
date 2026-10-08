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
    target: cmd/spire-server/cli/entry/create.go
---

# Create a registration entry

Register which software receives a SPIFFE ID: its parent, the selectors it
must match, and how its SVIDs are issued. Many entries can be created in one
request; each succeeds or fails on its own.
