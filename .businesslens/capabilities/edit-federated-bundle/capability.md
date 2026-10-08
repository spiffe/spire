---
domain: bundles
availability:
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

# Edit a federated bundle

Change some values of a foreign trust domain's bundle the server already
holds, keeping the rest.
