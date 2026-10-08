---
kind: primary
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: The Operator supplies the SPIFFE ID with optional DNS names and time to live
    kind: actor
    actor: operator
    entities: []
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product signs the X.509-SVID with the active X.509 authority
    kind: product
    actor: operator
    entities:
      - {entity: x509-svid, effect: creates, facts: [SPIFFE ID, Certificate chain, Private key, DNS names, Expires at, Hint]}
      - {entity: x509-authority, effect: reads, facts: [Authority ID]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Mint an X.509-SVID

## Trigger

An Operator needs a credential for software SPIRE does not attest.

## Outcome

The Operator holds the X.509-SVID, its private key and the trust domain's CA
certificates, printed or written to files.

## Edge cases

- A SPIFFE ID outside the trust domain is refused.
- A lifetime capped below the requested one is reported.
