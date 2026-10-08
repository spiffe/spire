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

# Append to the bundle

Add X.509 or JWT authorities to the server's own bundle, beside those the
server manages itself.
