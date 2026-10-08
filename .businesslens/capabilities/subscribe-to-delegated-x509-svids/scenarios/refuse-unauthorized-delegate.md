---
kind: validation
routes:
  del: Delegated Identity API
steps:
  - text: The Authorized delegate presents selectors
    kind: actor
    actor: authorized-delegate
    entities: []
    contexts:
      del: { place: delegated-identity-api }
  - text: "None of the caller's SPIFFE IDs is configured as an authorized delegate"
    kind: condition
    actor: authorized-delegate
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID]}
    contexts:
      del: { place: delegated-identity-api }
  - text: "The Product refuses with \"caller not configured as an authorized delegate\""
    kind: product
    actor: authorized-delegate
    entities: []
    contexts:
      del: { place: delegated-identity-api }
---

# A caller that is not an authorized delegate is refused

## Trigger

A process whose SPIFFE IDs are not among the authorized delegates calls the
API.

## Outcome

The request is refused with "caller not configured as an authorized delegate".

## Edge cases

- Presenting both selectors and a process ID, or neither, is refused.
- Authorization is checked again on every update of the stream.
