# Telemetry

The SPIRE Server and Agent can be configured to emit metrics that can be sent to the supported metrics collectors. For instructions on how to configure them properly, please refer to the [Telemetry Configuration](telemetry_config.md) guide.

The following metrics are emitted:

## SPIRE Server

| Type         | Keys                                             | Labels                       | Description                                                                           |
|--------------|--------------------------------------------------|------------------------------|---------------------------------------------------------------------------------------|
| Call Counter | `rpc`, `<service>`, `<method>`                   |                              | Call counters over the [SPIRE Server RPCs](https://github.com/spiffe/spire-api-sdk).  |
| Counter      | `bundle_manager`, `update`, `federated_bundle`   | `trust_domain_id`            | The bundle endpoint manager updated a federated bundle                                |
| Call Counter | `bundle_manager`, `fetch`, `federated_bundle`    | `trust_domain_id`            | The bundle endpoint manager is fetching federated bundle.                             |
| Call Counter | `ca`, `manager`, `bundle`, `prune`               |                              | The CA manager is pruning a bundle.                                                   |
| Counter      | `ca`, `manager`, `bundle`, `pruned`              |                              | The CA manager has successfully pruned a bundle.                                      |
| Call Counter | `ca`, `manager`, `jwt_key`, `prepare`            |                              | The CA manager is preparing a JWT Key.                                                |
| Counter      | `ca`, `manager`, `x509_ca`, `activate`           |                              | The CA manager has successfully activated an X.509 CA.                                |
| Call Counter | `ca`, `manager`, `x509_ca`, `prepare`            |                              | The CA manager is preparing an X.509 CA.                                              |
| Call Counter | `datastore`, `bundle`, `append`                  |                              | The Datastore is appending a bundle.                                                  |
| Call Counter | `datastore`, `bundle`, `count`                   |                              | The Datastore is counting bundles.                                                    |
| Call Counter | `datastore`, `bundle`, `create`                  |                              | The Datastore is creating a bundle.                                                   |
| Call Counter | `datastore`, `bundle`, `delete`                  |                              | The Datastore is deleting a bundle.                                                   |
| Call Counter | `datastore`, `bundle`, `fetch`                   |                              | The Datastore is fetching a bundle.                                                   |
| Call Counter | `datastore`, `bundle`, `list`                    |                              | The Datastore is listing bundles.                                                     |
| Call Counter | `datastore`, `bundle`, `prune`                   |                              | The Datastore is pruning a bundle.                                                    |
| Call Counter | `datastore`, `bundle`, `set`                     |                              | The Datastore is setting a bundle.                                                    |
| Call Counter | `datastore`, `bundle`, `update`                  |                              | The Datastore is updating a bundle.                                                   |
| Call Counter | `datastore`, `join_token`, `create`              |                              | The Datastore is creating a join token.                                               |
| Call Counter | `datastore`, `join_token`, `delete`              |                              | The Datastore is deleting a join token.                                               |
| Call Counter | `datastore`, `join_token`, `fetch`               |                              | The Datastore is fetching a join token.                                               |
| Call Counter | `datastore`, `join_token`, `prune`               |                              | The Datastore is pruning join tokens.                                                 |
| Call Counter | `datastore`, `node`, `count`                     |                              | The Datastore is counting nodes.                                                      |
| Call Counter | `datastore`, `node`, `create`                    |                              | The Datastore  is creating a node.                                                    |
| Call Counter | `datastore`, `node`, `delete`                    |                              | The Datastore is deleting a node.                                                     |
| Call Counter | `datastore`, `node`, `fetch`                     |                              | The Datastore is fetching nodes.                                                      |
| Call Counter | `datastore`, `node`, `list`                      |                              | The Datastore is listing nodes.                                                       |
| Call Counter | `datastore`, `node`, `selectors`, `fetch`        |                              | The Datastore is fetching selectors for a node.                                       |
| Call Counter | `datastore`, `node`, `selectors`, `list`         |                              | The Datastore is listing selectors for a node.                                        |
| Call Counter | `datastore`, `node`, `selectors`, `set`          |                              | The Datastore is setting selectors for a node.                                        |
| Call Counter | `datastore`, `node`, `update`                    |                              | The Datastore is updating a node.                                                     |
| Call Counter | `datastore`, `node_event`, `list`                |                              | The Datastore is listing node events.                                                 |
| Call Counter | `datastore`, `node_event`, `prune`               |                              | The Datastore is pruning expired node events.                                         |
| Call Counter | `datastore`, `node_event`, `fetch`               |                              | The Datastore is fetching a specific node event.                                      |
| Call Counter | `datastore`, `registration_entry`, `count`       |                              | The Datastore is counting registration entries.                                       |
| Call Counter | `datastore`, `registration_entry`, `create`      |                              | The Datastore is creating a registration entry.                                       |
| Call Counter | `datastore`, `registration_entry`, `delete`      |                              | The Datastore is deleting a registration entry.                                       |
| Call Counter | `datastore`, `registration_entry`, `fetch`       |                              | The Datastore is fetching registration entries.                                       |
| Call Counter | `datastore`, `registration_entry`, `list`        |                              | The Datastore is listing registration entries.                                        |
| Call Counter | `datastore`, `registration_entry`, `prune`       |                              | The Datastore is pruning registration entries.                                        |
| Call Counter | `datastore`, `registration_entry`, `update`      |                              | The Datastore is updating a registration entry.                                       |
| Call Counter | `datastore`, `registration_entry_event`, `list`  |                              | The Datastore is listing a registration entry events.                                 |
| Call Counter | `datastore`, `registration_entry_event`, `prune` |                              | The Datastore is pruning expired registration entry events.                           |
| Call Counter | `datastore`, `registration_entry_event`, `fetch` |                              | The Datastore is fetching a specific registration entry event.                        |
| Call Counter | `entry`, `cache`, `reload`                       |                              | The Server is reloading its in-memory entry cache from the datastore                 |
| Gauge |  `node`, `agents_by_id_cache`, `count`                  |                              | The Server is re-hydrating the agents-by-id event-based cache |
| Gauge |  `node`, `agents_by_expiresat_cache`, `count`           |                              | The Server is re-hydrating the agents-by-expiresat event-based cache  |
| Gauge | `node`, `skipped_node_event_ids`, `count`         |                              | The count of skipped ids detected in the last `sql_transaction_timout` period.  For databases that autoincrement ids by more than one, this number will overreport the skipped ids. [Issue](https://github.com/spiffe/spire/issues/5341) |
| Gauge | `entry`, `nodealiases_by_entryid_cache`, `count`        |                              | The Server is re-hydrating the nodealiases-by-entryid event-based cache |
| Gauge | `entry`, `nodealiases_by_selector_cache`, `count`       |                              | The Server is re-hydrating the nodealiases-by-selector event-based cache |
| Gauge | `entry`, `entries_by_entryid_cache`, `count`            |                              | The Server is re-hydrating the entries-by-entryid event-based cache |
| Gauge | `entry`, `entries_by_parentid_cache`, `count`           |                              | The Server is re-hydrating the entries-by-parentid event-based cache |
| Gauge | `entry`, `skipped_entry_event_ids`, `count`       |                              | The count of skipped ids detected in the last sql_transaction_timout period.  For databases that autoincrement ids by more than one, this number will overreport the skipped ids. [Issue](https://github.com/spiffe/spire/issues/5341)  |
| Counter      | `manager`, `jwt_key`, `activate`                 |                              | The CA manager has successfully activated a JWT Key.                                  |
| Gauge        | `manager`, `x509_ca`, `rotate`, `ttl`            | `trust_domain_id`            | The CA manager is rotating the X.509 CA with a given TTL for a specific Trust Domain. |
| Call Counter | `registration_entry`, `manager`, `prune`         |                              | The Registration manager is pruning entries.                                          |
| Counter      | `server_ca`, `sign`, `jwt_svid`                  |                              | The CA has successfully signed a JWT SVID.                                            |
| Counter      | `server_ca`, `sign`, `x509_ca_svid`              |                              | The CA has successfully signed an X.509 CA SVID.                                      |
| Counter      | `server_ca`, `sign`, `x509_svid`                 |                              | The CA has successfully signed an X.509 SVID.                                         |
| Call Counter | `svid`, `rotate`                                 |                              | The Server's SVID is being rotated.                                                   |
| Gauge        | `started`                                        | `version`, `trust_domain_id` | Information about the Server.                                                         |
| Gauge        | `uptime_in_ms`                                   |                              | The uptime of the Server in milliseconds.                                             |

## SPIRE Agent

| Type         | Keys                                                                     | Labels                       | Description                                                                           |
|--------------|--------------------------------------------------------------------------|------------------------------|---------------------------------------------------------------------------------------|
| Call Counter | `rpc`, `<service>`, `<method>`                                           |                              | Call counters over the [SPIRE Agent RPCs](<https://github.com/spiffe/spire-api-sdk>). |
| Call Counter | `agent_key_manager`, `generate_key_pair`                                 |                              | The KeyManager is generating a key pair.                                              |
| Call Counter | `agent_key_manager`, `fetch_private_key`                                 |                              | The KeyManager is fetching a private key.                                             |
| Call Counter | `agent_key_manager`, `store_private_key`                                 |                              | The KeyManager is storing a private key.                                              |
| Call Counter | `agent_svid`, `rotate`                                                   |                              | The Agent's SVID is being rotated.                                                    |
| Sample       | `cache_manager`, `expiring_svids`                                        |                              | The number of expiring SVIDs that the Cache Manager has.                              |
| Sample       | `cache_manager`, `outdated_svids`                                        |                              | The number of outdated SVIDs that the Cache Manager has.                              |
| Counter      | `lru_cache_entry_add`                                                    |                              | The number of entries added to the LRU cache.                                         |
| Counter      | `lru_cache_entry_remove`                                                 |                              | The number of entries removed from the LRU cache.                                     |
| Counter      | `lru_cache_entry_update`                                                 |                              | The number of entries updated in the LRU cache.                                       |
| Call Counter | `manager`, `sync`, `fetch_entries_updates`                               |                              | The Sync Manager is fetching entries updates.                                         |
| Call Counter | `manager`, `sync`, `fetch_svids_updates`                                 |                              | The Sync Manager is fetching SVIDs updates.                                           |
| Call Counter | `node`, `attestor`, `new_svid`                                           |                              | The Node Attestor is calling to get an SVID.                                          |
| Gauge        | `lru_cache_record_map_size`                                              |                              | The total number of entries in the LRU cache records map.                             |
| Counter      | `sds_api`, `connections`                                                 |                              | The SDS API has successfully established a connection.                                |
| Gauge        | `sds_api`, `connections`                                                 |                              | The number of active connection that the SDS API has.                                 |
| Gauge        | `lru_cache_svid_map_size`                                                |                              | The total number of SVIDs in the LRU cache SVID map.                                  |
| Counter      | `workload_api`, `bundles_update`, `jwt`                                  |                              | The Workload API has successfully updated a JWT bundle.                               |
| Counter      | `workload_api`, `connection`                                             |                              | The Workload API has successfully established a new connection.                       |
| Gauge        | `workload_api`, `connections`                                            |                              | The number of active connections that the Workload API has.                           |
| Sample       | `workload_api`, `discovered_selectors`                                   |                              | The number of selectors discovered during a workload attestation process.             |
| Call Counter | `workload_api`, `workload_attestation`                                   |                              | The Workload API is performing a workload attestation.                                |
| Call Counter | `workload_api`, `workload_attestor`                                      | `attestor`                   | The Workload API is invoking a given attestor.                                        |
| Gauge        | `started`                                                                | `version`, `trust_domain_id` | Information about the Agent.                                                          |
| Gauge        | `uptime_in_ms`                                                           |                              | The uptime of the Agent in milliseconds.                                              |
| Counter      | `delegated_identity_api`, `connection`                                   |                              | The Delegated Identity API has successfully established a connection.                 |
| Gauge        | `delegated_identity_api`, `connections`                                  |                              | The number of active connection that the Delegated Identity API has.                  |
| Latency      | `delegated_identity_api`, `subscribe_x509_svid` `first_x509_svid_update` |                              | The latency fetching first X.509-SVID in Delegated Identity API.                      |

Note: These are the keys and labels that SPIRE emits, but the format of the
metric once ingested could vary depending on the metric collector. For example,
in StatsD, the metric emitted when rotating an Agent SVID (`agent_svid`,
`rotate`) can be found as
`spire_agent_agent_svid_rotate_internal_host-agent-0`, where `host-agent-0` is
the hostname and `spire-agent` is the service name.

## Call Counters

Call counters are aggregate metric types that emit several metrics related to
the issuance of a "call" to a method or RPC. The following metrics are
produced for a call counter:

- A counter representing the number of calls using the call counter key
- A sample of the elapsed time for the call using the call counter
  key+`".elapsed_time"`

Additionally, the metrics emitted above each carry a `status` label (in
addition to any other labels for specific to the individual call counter) that
holds the [gRPC status code](https://pkg.go.dev/google.golang.org/grpc/codes#Code)
of the call.

For example, a successful invocation of the SPIRE Server `AttestAgent` RPC
would produce the following metrics:

```text
spire_server.rpc.agent.v1.agent.attest_agent:1|c|#status:OK
spire_server.rpc.agent.v1.agent.attest_agent.elapsed_time:1.045773|ms|#status:OK
```
