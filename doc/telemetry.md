# Telemetry

The SPIRE Server and Agent can be configured to emit metrics that can be sent to the supported metrics collectors. For instructions on how to configure them properly, please refer to the [Telemetry Configuration](telemetry_config.md) guide.

The following metrics are emitted:

## SPIRE Server

| Type | Keys | Labels | Description |
| ---  | --- | --- | --- |
| Call Counter | `rpc`, `<service>`, `<method>` | | Call counters over the SPIRE Server RPCs (other than the deprecated Node and Registration APIs)
| Call Counter | `ca`, `manager`, `bundle`, `prune` | | The CA manager is pruning a bundle.
| Counter | `ca`, `manager`, `bundle`, `pruned` | | The CA manager has successfully pruned a bundle.
| Call Counter | `ca`, `manager`, `jwt_key`, `prepare` | | The CA manager is preparing a JWT Key.
| Counter | `ca`, `manager`, `x509_ca`, `activate` | | The CA manager has successfully activated an X.509 CA.
| Call Counter | `ca`, `manager`, `x509_ca`, `prepare` | | The CA manager is preparing an X.509 CA.
| Call Counter | `datastore`, `bundle`, `append` | | The Datastore is appending a bundle.
| Call Counter | `datastore`, `bundle`, `count` | | The Datastore is counting bundles.
| Call Counter | `datastore`, `bundle`, `create` | | The Datastore is creating a bundle.
| Call Counter | `datastore`, `bundle`, `delete` | | The Datastore is deleting a bundle.
| Call Counter | `datastore`, `bundle`, `fetch` | | The Datastore is fetching a bundle.
| Call Counter | `datastore`, `bundle`, `list` | | The Datastore is listing bundles.
| Call Counter | `datastore`, `bundle`, `prune` | | The Datastore is pruning a bundle.
| Call Counter | `datastore`, `bundle`, `set` | | The Datastore is setting a bundle.
| Call Counter | `datastore`, `bundle`, `update` | | The Datastore is updating a bundle.
| Call Counter | `datastore`, `join_token`, `create` | | The Datastore is creating a join token.
| Call Counter | `datastore`, `join_token`, `delete` | | The Datastore is deleting a join token.
| Call Counter | `datastore`, `join_token`, `fetch` | | The Datastore is fetching a join token.
| Call Counter | `datastore`, `join_token`, `prune` | | The Datastore is pruning join tokens.
| Call Counter | `datastore`, `node`, `count` | | The Datastore is counting nodes.
| Call Counter | `datastore`, `node`, `create` | | The Datastore  is creating a node.
| Call Counter | `datastore`, `node`, `delete` | | The Datastore is deleting a node.
| Call Counter | `datastore`, `node`, `fetch` | | The Datastore is fetching nodes.
| Call Counter | `datastore`, `node`, `list` | | The Datastore is listing nodes.
| Call Counter | `datastore`, `node`, `selectors`, `fetch` | | The Datastore is fetching selectors for a node.
| Call Counter | `datastore`, `node`, `selectors`, `list` | | The Datastore is listing selectors for a node.
| Call Counter | `datastore`, `node`, `selectors`, `set` | | The Datastore is setting selectors for a node.
| Call Counter | `datastore`, `node`, `update` | | The Datastore is updating a node.
| Call Counter | `datastore`, `registration_entry`, `count` | | The Datastore is counting registration entries.
| Call Counter | `datastore`, `registration_entry`, `create` | | The Datastore is creating a registration entry.
| Call Counter | `datastore`, `registration_entry`, `delete` | | The Datastore is deleting a registration entry.
| Call Counter | `datastore`, `registration_entry`, `fetch` | | The Datastore is fetching registration entries.
| Call Counter | `datastore`, `registration_entry`, `list` | | The Datastore is listing registration entries.
| Call Counter | `datastore`, `registration_entry`, `prune` | | The Datastore is pruning registration entries.
| Call Counter | `datastore`, `registration_entry`, `update` | | The Datastore is updating a registration entry. 
| Counter | `manager`, `jwt_key`, `activate` | | The CA manager has successfully activated a JWT Key.
| Gauge | `manager`, `x509_ca`, `rotate`, `ttl` | `trust_domain_id` | The CA manager is rotating the X.509 CA with a given TTL for a specific Trust Domain.
| Call Counter | `node_api`, `attest` | | The Node API is performing a node attestation.
| Call Counter | `node_api`, `authorize_call` | `method` | The Node API is authorizing a call for a given method.
| Call Counter | `node_api`, `fetch_bundle`, `fetch` | | The Node API is fetching the current bundle.
| Call Counter | `node_api`, `jwt_key`, `push` | | The Node API is pushing a JWT Key to an upstream server.
| Call Counter | `node_api`, `jwt_svid`, `fetch` | | The Node API is fetching a JWT SVID.
| Call Counter | `node_api`, `x509_ca_svid`, `fetch` | | The Node API is fetching an X.509 CA SVID.
| Call Counter | `node_api`, `x509_svid`, `fetch` | | The Node API is fetching an X.509 SVID.
| Call Counter | `registration_api`, `authorize_call` | `method` | The Registration API is authorizing a call for a given method.
| Call Counter | `registration_api`, `bundle`, `fetch` | | The Registration API is fetching a bundle.
| Call Counter | `registration_api`, `entry`, `create` | | The Registration API is creating an entry.
| Call Counter | `registration_api`, `entry`, `create_if_not_exists` | | The Registration API is creating an entry if it doesn't already exist.
| Call Counter | `registration_api`, `entry`, `delete` | | The Registration API is deleting an entry.
| Call Counter | `registration_api`, `entry`, `fetch` | | The Registration API is fetching an entry.
| Call Counter | `registration_api`, `entry`, `list` | | The Registration API is listing entries.
| Call Counter | `registration_api`, `entry`, `update` | | The Registration API is updating an entry.
| Counter | `registration_api`, `entry`, `updated` | | The Registration API has successfully updated an entry.
| Call Counter | `registration_api`, `federated_bundle`, `create` | | The Registration API is creating a federated bundle.
| Call Counter | `registration_api`, `federated_bundle`, `delete` | | The Registration API is deleting a federated bundle.
| Call Counter | `registration_api`, `federated_bundle`, `fetch` | | The Registration API is fetching a federated bundle.
| Call Counter | `registration_api`, `federated_bundle`, `list` | | The Registration API is listing federated bundles.
| Call Counter | `registration_api`, `federated_bundle`, `update` | | The Registration API is updating a federated bundle.
| Call Counter | `registration_api`, `join_token`, `create` | | The Registration API is creating a join token.
| Call Counter | `registration_api`, `jwt_svid`, `mint` | | The Registration API is minting a JWT SVID.
| Call Counter | `registration_api`, `x509_svid`, `mint` | | The Registration API is minting an X.509 SVID.
| Call Counter | `registration_entry`, `manager`, `prune` | | The Registration manager is pruning entries.
| Counter | `server_ca`, `sign`, `jwt_svid` | | The CA has successfully signed a JWT SVID.
| Counter | `server_ca`, `sign`, `x509_ca_svid` | | The CA has successfully signed an X.509 CA SVID.
| Counter | `server_ca`, `sign`, `x509_svid` | | The CA has successfully signed an X.509 SVID.
| Call Counter | `svid`, `rotate` | | The Server's SVID is being rotated.
| Gauge | `started` | `version` | | The version of the Server.

## SPIRE Agent

| Type | Keys | Labels | Description |
| ---  | --- | --- | --- |
| Call Counter | `rpc`, `<service>`, `<method>` | | Call counters over the SPIRE Agent RPCs
| Call Counter | `agent_key_manager`, `generate_key_pair` | | The KeyManager is generating a key pair.
| Call Counter | `agent_key_manager`, `fetch_private_key` | | The KeyManager is fetching a private key.
| Call Counter | `agent_key_manager`, `store_private_key` | | The KeyManager is storing a private key.
| Call Counter | `agent_svid`, `rotate` | | The Agent's SVID is being rotated.
| Sample | `cache_manager`, `expiring_svids` | | The number of expiring SVIDs that the Cache Manager has.
| Sample | `cache_manager`, `outdated_svids` | | The number of outdated SVIDs that the Cache Manager has.
| Call Counter | `manager`, `sync`, `fetch_entries_updates` | | The Sync Manager is fetching entries updates.
| Call Counter | `manager`, `sync`, `fetch_svids_updates` | | The Sync Manager is fetching SVIDs updates.
| Call Counter | `node`, `attestor`, `new_svid` | | The Node Attestor is calling to get an SVID.
| Counter | `sds_api`, `connections` | | The SDS API has successfully established a connection.
| Gauge | `sds_api`, `connections` | | The number of active connection that the SDS API has.
| Counter | `workload_api`, `bundles_update`, `jwt` | | The Workload API has successfully updated a JWT bundle.
| Counter | `workload_api`, `connection` | | The Workload API has successfully established a new connection.
| Gauge | `workload_api`, `connections` | | The number of active connections that the Workload API has. 
| Sample | `workload_api`, `discovered_selectors` | | The number of selectors discovered during a workload attestation process.
| Call Counter | `workload_api`, `workload_attestation` | | The Workload API is performing a workload attestation.
| Call Counter | `workload_api`, `workload_attestor` | `attestor` | The Workload API is invoking a given attestor.
| Gauge | `started` | `version` | The version of the Agent.

Note: These are the keys and labels that SPIRE emits, but the format of the metric once ingested could vary depending on the metric collector. E.g. once in StatsD, the metric emitted when rotating an Agent SVID (`agent_svid`, `rotate`) can be found as `spire_agent_agent_svid_rotate_internal_host-agent-0`, where `host-agent-0` is the hostname and `spire-agent` is the service name.
