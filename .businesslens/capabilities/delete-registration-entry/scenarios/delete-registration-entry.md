---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator identifies the entry by its Entry ID
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product removes the registration entry
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: removes}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Delete a registration entry

## Trigger

An Operator no longer wants software to receive an entry's identity.

## Outcome

The registration entry is gone; agents stop issuing and serving its SVIDs at
their next sync, while SVIDs already issued stay valid until they expire.

## Edge cases

- An unknown Entry ID is refused with "entry not found".
