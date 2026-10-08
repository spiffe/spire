---
domain: logger
references:
  - kind: code
    role: implementation
    target: pkg/server/api/logger/v1/service.go
  - kind: code
    role: implementation
    target: pkg/agent/api/logger/v1/service.go
---

# Logger

The logging level of one running SPIRE Server or SPIRE Agent, which an
Operator can change without restarting it.

## Information kept

- **Current level** — the logging level in effect
- **Launch level** — the level the configuration set when the component started
