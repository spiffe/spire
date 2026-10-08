---
availability:
  - place: server-cli
  - place: "server-api::administration"
  - place: agent-cli
  - place: health-checks
references:
  - kind: code
    role: implementation
    target: cmd/spire-server/cli/healthcheck/healthcheck.go
  - kind: code
    role: implementation
    target: cmd/spire-agent/cli/healthcheck/healthcheck.go
  - kind: code
    role: implementation
    target: pkg/server/api/health/v1/service.go
  - kind: code
    role: implementation
    target: pkg/agent/api/health/v1/service.go
  - kind: code
    role: implementation
    target: pkg/common/health/health.go
---

# Check health

Check whether a SPIRE Server or SPIRE Agent is serving, from its command line
or, when HTTP health checks are enabled, through its liveness and readiness
paths.
