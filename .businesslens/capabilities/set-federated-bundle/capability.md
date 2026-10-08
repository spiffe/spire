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
    target: cmd/spire-server/cli/bundle/set.go
---

# Set a federated bundle

Create or replace the bundle of a foreign trust domain from PEM or SPIFFE
data. The server's own bundle cannot be set this way.
