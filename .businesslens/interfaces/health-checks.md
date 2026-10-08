---
type: api
actors:
  - health-checker
references:
  - kind: code
    role: implementation
    target: pkg/common/health/health.go
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: Health check configuration
---

# HTTP health checks

The HTTP listener a SPIRE Server, SPIRE Agent or OIDC Discovery Provider
serves when its `health_checks` section enables it, with one path for liveness
and one for readiness.
