---
kind: validation
routes:
  wapi: Workload API
steps:
  - text: The Workload submits the token and the audience it expects
    kind: actor
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
  - text: The Product refuses the token with the reason it is invalid
    kind: product
    actor: workload
    entities:
      - {entity: bundle, effect: reads, facts: [JWT authorities]}
    contexts:
      wapi: { place: workload-api }
---

# An invalid JWT-SVID is rejected

## Trigger

A token is expired, for another audience, or signed by an authority the caller
does not trust.

## Outcome

The workload is told the token is invalid and why.

## Edge cases

- A missing audience or token is refused before validation.
