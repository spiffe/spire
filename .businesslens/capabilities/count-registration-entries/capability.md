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
---

# Count registration entries

Report how many registration entries exist, optionally narrowed by the same
filters as showing them.
