---
kind: unattended
routes:
  cli: Server CLI
  api: Server API
steps:
  - text: "A registration entry's expiry has passed at the server's periodic check"
    kind: condition
    unattended: true
    entities:
      - {entity: registration-entry, effect: reads, facts: [Entry expiry]}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
  - text: The Product removes the expired registration entry
    kind: product
    entities:
      - {entity: registration-entry, effect: removes}
    contexts:
      cli: { place: server-cli }
      api: { place: "server-api::administration" }
---

# Expired registration entries are pruned

## Trigger

Every five minutes the server looks for registration entries whose expiry has
passed.

## Outcome

Entries past their expiry are removed and no longer shown.
