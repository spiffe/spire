# Migrating Registration API Clients

The `registration` API has been deprecated and removed. The new API surface is
a superset of the previous functionality and provides consistent semantics,
batch, and paging support.

This document outlines the replacement RPCs when migrating clients away from
the old registration API.

## Replacement RPCs

| Registration RPC          | Replacement RPC                     | Notes                                                                                             |
|---------------------------|-------------------------------------|---------------------------------------------------------------------------------------------------|
| `CreateEntry`             | `Entry.BatchCreateEntry`            |                                                                                                   |
| `CreateEntryIfNotExists`  | `Entry.BatchCreateEntry`            | The result code for the entry is ALREADY_EXISTS when the entry is preexisting.                    |
| `DeleteEntry`             | `Entry.BatchDeleteEntry`            |                                                                                                   |
| `FetchEntry`              | `Entry.GetEntry`                    |                                                                                                   |
| `FetchEntries`            | `Entry.ListEntries`                 |                                                                                                   |
| `UpdateEntry`             | `Entry.BatchUpdateEntry`            |                                                                                                   |
| `ListByParentID`          | `Entry.ListEntries`                 | See the `by_parent_id` filter.                                                                    |
| `ListBySelector`          | `Entry.ListEntries`                 | See the `by_selectors` filter.                                                                    |
| `ListBySelectors`         | `Entry.ListEntries`                 | See the `by_selectors` filter.                                                                    |
| `ListBySpiffeID`          | `Entry.ListEntries`                 | See the `by_spiffe_id` filter.                                                                    |
| `ListAllEntriesWithPages` | `Entry.ListEntries`                 | See the `page_size` / `page_token` fields.                                                        |
| `CreateFederatedBundle`   | `Bundle.BatchCreateFederatedBundle` | Alternatively, `Bundle.BatchSetFederatedBundle` can be used to "upsert" the federated bundle.     |
| `FetchFederatedBundle`    | `Bundle.GetFederatedBundle`         |                                                                                                   |
| `ListFederatedBundles`    | `Bundle.ListFederatedBundles`       |                                                                                                   |
| `UpdateFederatedBundle`   | `Bundle.BatchUpdateFederatedBundle` | Alternatively, `Bundle.BatchSetFederatedBundle` can be used to "upsert" the federated bundle.     |
| `DeleteFederatedBundle`   | `Bundle.BatchDeleteFederatedBundle` |                                                                                                   |
| `CreateJoinToken`         | `Agent.CreateJoinToken`             |                                                                                                   |
| `FetchBundle`             | `Bundle.GetBundle`                  |                                                                                                   |
| `EvictAgent`              | `Agent.DeleteAgent`                 | See the `Agent.BanAgent` RPC for a similar but distinct operation.                                |
| `ListAgents`              | `Agent.ListAgents`                  | Implementors must assume the RPC can page results arbitrarily, as deemed necessary by the server. |
| `MintX509SVID`            | `SVID.MintX509SVID`                 |                                                                                                   |
| `MintJWTSVID`             | `SVID.MintJWTSVID`                  |                                                                                                   |
| `GetNodeSelectors`        | `Agent.GetAgent`                    | Selectors are included in the agent information, unless explicitly filtered.                      |

## List Operations

Unlike the Registration API (except `ListAllEntriesWithPages`),
the new APIs `List*` operations all support paging. If clients provide a page
size, the server _will_ page the response, using the page size as an upper bound.
However, even if clients do not provide a page size, the server is free to
page the results. As such, clients must always be prepared to handle a paged
response.

## Batch Operation Results

It is important to note that the batch RPCs will not return a non-OK status
unless there was a problem encountered outside of application of a single batch
operation. Instead, individual batch operation results are communicated via
per-batch operation results. Migrators should be careful to do proper error
checking of not only the RPC result code, but the individual batch operation
result codes. See the individual RPC documentation for the batching semantics.
