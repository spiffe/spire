---
domain: bundles
availability:
  - place: server-cli
  - place: "server-api::administration"
  - place: "server-api::agents"
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
    target: cmd/spire-server/cli/bundle/list.go
---

# List federated bundles

List the bundles of foreign trust domains the server holds, or show one by
trust domain. The server's own bundle is never among them. An attested agent
fetches the federated bundles its entries need the same way.
