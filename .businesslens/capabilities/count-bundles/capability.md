---
domain: bundles
availability:
  - place: server-cli
  - place: "server-api::administration"
references:
  - kind: code
    role: implementation
    target: pkg/server/api/bundle/v1/service.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server bundle
---

# Count bundles

Report how many bundles the server holds, its own included.
