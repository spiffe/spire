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
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/bundle/delete.go
---

# Delete a federated bundle

Remove a foreign trust domain's bundle. A mode decides what happens to
registration entries that federate with it: restrict refuses, dissociate
removes the federation from them, delete removes them too.
