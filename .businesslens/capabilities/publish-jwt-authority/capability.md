---
availability:
  - place: "server-api::downstream"
references:
  - kind: code
    role: implementation
    target: "pkg/server/api/bundle/v1/service.go#PublishJWTAuthority"
  - kind: code
    role: implementation
    target: "pkg/server/ca/manager/manager.go#PublishJWTKey"
---

# Publish a JWT authority

A downstream server publishes its JWT signing key so that JWT-SVIDs it signs
verify across the whole nested deployment. The key travels up to the top
server's bundle.
