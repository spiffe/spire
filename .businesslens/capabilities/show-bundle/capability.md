---
domain: bundles
availability:
  - place: server-cli
  - place: "server-api::administration"
  - place: "server-api::bootstrap"
  - place: "server-api::agents"
  - place: "server-api::downstream"
  - place: bundle-endpoint
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
    target: cmd/spire-server/cli/bundle/show.go
  - kind: code
    role: implementation
    target: pkg/server/endpoints/bundle/server.go
  - kind: code
    role: implementation
    target: pkg/agent/client/client.go
---

# Show the bundle

Get the server's own trust domain bundle. Anyone who can reach the Server API
may fetch it, and the SPIFFE bundle endpoint serves it to foreign trust
domains in SPIFFE format with the configured refresh hint.
