---
relations:
  - entity: bundle
    verb: federates-with
    cardinality: many-to-many
references:
  - kind: code
    role: implementation
    target: pkg/server/api/entry/v1/service.go
  - kind: code
    role: implementation
    target: "cmd/spire-server/cli/entry/util.go#printEntry"
  - kind: doc
    role: intent
    target: doc/spire_server.md
    title: spire-server entry create
---

# Registration entry

A rule that gives a SPIFFE ID to software matching a set of selectors under a
parent. The parent is an agent, another entry's SPIFFE ID, or the server
itself for node entries, which give every matching agent an additional
identity (a node alias) that other entries can name as their parent.

## Information kept

- **Entry ID** — the identifier of the entry, generated unless the creator supplies one
- **SPIFFE ID** — the identity issued to matching software
- **Parent ID** — the agent, node alias or server whose software this entry covers
- **Selectors** — what attestation must find for software to match; all must be satisfied
- **X509-SVID TTL** — lifetime of X.509-SVIDs issued from the entry, or the server default
- **JWT-SVID TTL** — lifetime of JWT-SVIDs issued from the entry, or the server default
- **Federates with** — foreign trust domains whose bundles matching software receives
- **Admin** — whether the SPIFFE ID may administer the Server API
- **Downstream** — whether the SPIFFE ID belongs to a downstream SPIRE Server
- **DNS names** — DNS names included in X.509-SVIDs issued from the entry
- **Hint** — a label that tells apart a workload's identities with the same SPIFFE ID
- **Entry expiry** — when the server prunes the entry
- **Store SVID** — whether its SVIDs are written to an SVID store instead of being served to workloads
- **Disable X509-SVID prefetch** — whether the agent waits for a workload to ask before having its X.509-SVID signed
- **JWT-SVID include JTI** — whether each JWT-SVID carries a unique token ID, so cached tokens are not reused
- **Revision** — increases with every change, so agents notice the update
- **Created at** — when the entry was created; the older of two entries with the same hint wins
