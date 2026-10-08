---
kind: validation
routes:
  wapi: Workload API
steps:
  - text: The Workload asks for a JWT token without an audience
    kind: actor
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
  - text: "The Product refuses with \"audience must be specified\""
    kind: product
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
---

# A JWT-SVID without audience is refused

## Trigger

A workload asks for a JWT-SVID without naming an audience.

## Outcome

No token is returned.
