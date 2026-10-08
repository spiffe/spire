---
kind: alternative
routes:
  hc: HTTP health checks
steps:
  - text: The Health checker requests the liveness or readiness path
    kind: actor
    actor: health-checker
    entities: []
    contexts:
      hc: { place: health-checks }
  - text: "The Product answers with success only when every subsystem is live or ready, with each subsystem's details"
    kind: product
    actor: health-checker
    entities: []
    contexts:
      hc: { place: health-checks }
---

# Probe liveness and readiness over HTTP

## Trigger

A container orchestrator probes a component whose `health_checks` listener is
enabled.

## Outcome

The checker learns whether the component is live or ready and why not.
