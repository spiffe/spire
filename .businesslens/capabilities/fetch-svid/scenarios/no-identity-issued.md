---
kind: validation
routes:
  wapi: Workload API
steps:
  - text: The Workload asks for its SVIDs
    kind: actor
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
  - text: "No registration entry's selectors match the calling process"
    kind: condition
    actor: workload
    entities:
      - {entity: registration-entry, effect: reads, facts: [Selectors]}
    contexts:
      wapi: { place: workload-api }
  - text: "The Product refuses with \"no identity issued\""
    kind: product
    actor: workload
    entities: []
    contexts:
      wapi: { place: workload-api }
---

# A process with no matching entry gets no identity

## Trigger

A process that no registration entry matches asks for SVIDs.

## Outcome

The request is refused with "no identity issued".

## Edge cases

- A request without the Workload API security header is refused with "security header missing from request".
