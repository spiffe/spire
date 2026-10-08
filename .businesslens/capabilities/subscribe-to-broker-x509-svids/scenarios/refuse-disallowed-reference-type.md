---
kind: validation
routes:
  brk: SPIFFE Broker API
steps:
  - text: "The Broker sends a reference of a type it is not allowed to use, or over TCP without permission"
    kind: actor
    actor: broker
    entities: []
    contexts:
      brk: { place: broker-api }
  - text: The Product refuses the request before attesting the reference
    kind: product
    actor: broker
    entities: []
    contexts:
      brk: { place: broker-api }
---

# A reference type the broker may not use is refused

## Trigger

The broker's configuration does not allow the reference type, or does not
allow it over TCP.

## Outcome

No identity is disclosed: "broker is not allowed to use reference type".
