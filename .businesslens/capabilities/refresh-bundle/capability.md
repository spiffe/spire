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
    target: pkg/server/bundle/client/manager.go
  - kind: code
    role: implementation
    target: pkg/server/bundle/client/updater.go
---

# Refresh a federated bundle

Fetch a foreign trust domain's bundle from its bundle endpoint. An Operator
can ask for it now; the server otherwise refreshes every trust domain it
federates with on its own, guided by the bundle's refresh hint.
