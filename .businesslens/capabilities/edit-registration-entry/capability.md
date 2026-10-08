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
    target: cmd/spire-server/cli/entry/update.go
---

# Edit a registration entry

Change an existing registration entry identified by its Entry ID. The command
line replaces every value of the entry with what it is given; through the
Server API a caller may name the values to change and keep the rest.
