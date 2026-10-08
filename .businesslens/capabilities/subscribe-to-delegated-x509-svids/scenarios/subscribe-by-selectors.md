---
kind: primary
routes:
  del: Delegated Identity API
steps:
  - text: The Authorized delegate presents selectors it attested
    kind: actor
    actor: authorized-delegate
    entities: []
    contexts:
      del: { place: delegated-identity-api }
  - text: The Product attests the caller and checks its SPIFFE ID against the configured authorized delegates
    kind: product
    actor: authorized-delegate
    entities: []
    contexts:
      del: { place: delegated-identity-api }
  - text: "The Product streams the X.509-SVIDs of the registration entries matching the selectors, except admin and downstream entries"
    kind: product
    actor: authorized-delegate
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, Selectors, Admin, Downstream, Federates with]}
      - {entity: x509-svid, effect: reads, facts: [SPIFFE ID, Certificate chain, Private key, DNS names, Expires at, Hint]}
    contexts:
      del: { place: delegated-identity-api }
---

# Subscribe by selectors

## Trigger

An authorized delegate, such as a node proxy, has attested a process itself.

## Outcome

The delegate holds the X.509-SVIDs of every registration entry matching the
selectors and receives each rotation.

## Edge cases

- The delegate is responsible for the selectors it presents.
