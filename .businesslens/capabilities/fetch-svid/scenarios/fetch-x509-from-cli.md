---
kind: alternative
routes:
  cli: Agent CLI
steps:
  - text: "The Operator asks for the X.509 identities of the command's own process"
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: agent-cli }
  - text: "The Product attests the command's process and returns the X.509-SVIDs and bundles for its matching entries"
    kind: product
    actor: operator
    entities:
      - {entity: registration-entry, effect: reads, facts: [SPIFFE ID, Selectors]}
      - {entity: x509-svid, effect: reads, facts: [SPIFFE ID, Certificate chain, Private key, DNS names, Expires at, Hint]}
      - {entity: bundle, effect: reads, facts: [Trust domain, X.509 authorities]}
    contexts:
      cli: { place: agent-cli }
---

# Fetch or watch X.509-SVIDs from the command line

## Trigger

An Operator checks what identities a process on the node receives.

## Outcome

The Operator sees, or writes to files, each X.509-SVID with its key and
bundles; watching keeps printing each update as it arrives.
