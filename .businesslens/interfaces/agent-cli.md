---
type: cli
actors:
  - operator
references:
  - kind: code
    role: implementation
    target: cmd/spire-agent/cli/cli.go
  - kind: doc
    role: intent
    target: doc/spire_agent.md
    title: Command line options
---

# SPIRE Agent command line

The `spire-agent` command line an Operator runs on a node. Its `api` commands
fetch, watch and validate identities through the local Workload API as the
command's own process; its other commands check the agent's health, validate
its configuration, and get its debug information and logging level through the
Agent Admin API socket.
