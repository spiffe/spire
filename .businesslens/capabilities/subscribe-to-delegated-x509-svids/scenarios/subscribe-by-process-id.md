---
kind: alternative
routes:
  del: Delegated Identity API
steps:
  - text: The Authorized delegate presents a process ID
    kind: actor
    actor: authorized-delegate
    entities: []
    contexts:
      del: { place: delegated-identity-api }
  - text: The Product attests the process itself and streams the X.509-SVIDs of its matching registration entries
    kind: product
    actor: authorized-delegate
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, Selectors]}
      - {entity: x509-svid, effect: reads, facts: [SPIFFE ID, Certificate chain, Private key, DNS names, Expires at, Hint]}
    contexts:
      del: { place: delegated-identity-api }
---

# Subscribe by process ID

## Trigger

An authorized delegate knows the process ID of a process on the node.

## Outcome

The delegate holds the X.509-SVIDs of the entries matching what the agent
attested for that process.

## Edge cases

- The delegate must ensure the process ID is not reused while the request is answered.
