# Telemetry

The SPIRE Server and Agent can be configured to emit metrics that can be send to the supported metrics collectors. For instructions on how to configure them properly please refer to the [Telemetry Configuration](telemetry_config) guide.

The following metrics are emited:

## SPIRE Server

| Type | Keys | Labels |
| ---  | --- | --- |
| Call Counter | `ca`, `manager`, `bundle`, `prune` |
| Counter | `ca`, `manager`, `bundle`, `pruned` |
| Call Counter | `ca`, `manager`, `jwt_key`, `prepare` |
| Counter | `ca`, `manager`, `x509_ca`, `activate` |
| Call Counter | `ca`, `manager`, `x509_ca`, `prepare` |
| Call Counter | `datastore`, `bundle`, `append` |
| Call Counter | `datastore`, `bundle`, `create` |
| Call Counter | `datastore`, `bundle`, `delete` |
| Call Counter | `datastore`, `bundle`, `fetch` |
| Call Counter | `datastore`, `bundle`, `list` |
| Call Counter | `datastore`, `bundle`, `prune` |
| Call Counter | `datastore`, `bundle`, `set` |
| Call Counter | `datastore`, `bundle`, `update` |
| Call Counter | `datastore`, `join_token`, `create` |
| Call Counter | `datastore`, `join_token`, `delete` |
| Call Counter | `datastore`, `join_token`, `fetch` |
| Call Counter | `datastore`, `join_token`, `prune` |
| Call Counter | `datastore`, `node`, `create` |
| Call Counter | `datastore`, `node`, `delete` |
| Call Counter | `datastore`, `node`, `fetch` |
| Call Counter | `datastore`, `node`, `list` |
| Call Counter | `datastore`, `node`, `selectors`, `fetch` |
| Call Counter | `datastore`, `node`, `selectors`, `set` |
| Call Counter | `datastore`, `node`, `update` |
| Call Counter | `datastore`, `registration_entry`, `create` |
| Call Counter | `datastore`, `registration_entry`, `delete` |
| Call Counter | `datastore`, `registration_entry`, `fetch` |
| Call Counter | `datastore`, `registration_entry`, `list` |
| Call Counter | `datastore`, `registration_entry`, `prune` |
| Call Counter | `datastore`, `registration_entry`, `update` |
| Counter | `manager`, `jwt_key`, `activate` |
| Gauge | `manager`, `x509_ca`, `rotate`, `ttl` | `trust_domain_id` |
| Call Counter | `node_api`, `attest` |
| Call Counter | `node_api`, `authorize_call` | `method` |
| Call Counter | `node_api`, `fetch_bundle`, `fetch` |
| Call Counter | `node_api`, `jwt_key`, `push` |
| Call Counter | `node_api`, `jwt_svid`, `fetch` |
| Call Counter | `node_api`, `x509_ca_svid`, `fetch` |
| Call Counter | `node_api`, `x509_svid`, `fetch` |
| Call Counter | `registration_api`, `authorize_call` | `method` |
| Call Counter | `registration_api`, `bundle`, `fetch` |
| Call Counter | `registration_api`, `entry`, `create` |
| Call Counter | `registration_api`, `entry`, `create_if_not_exists` |
| Call Counter | `registration_api`, `entry`, `delete` |
| Call Counter | `registration_api`, `entry`, `fetch` |
| Call Counter | `registration_api`, `entry`, `list` |
| Call Counter | `registration_api`, `entry`, `update` |
| Counter | `registration_api`, `entry`, `updated` |
| Call Counter | `registration_api`, `federated_bundle`, `create` |
| Call Counter | `registration_api`, `federated_bundle`, `delete` |
| Call Counter | `registration_api`, `federated_bundle`, `fetch` |
| Call Counter | `registration_api`, `federated_bundle`, `list` |
| Call Counter | `registration_api`, `federated_bundle`, `update` |
| Call Counter | `registration_api`, `join_token`, `create` |
| Call Counter | `registration_api`, `jwt_svid`, `mint` |
| Call Counter | `registration_api`, `x509_svid`, `mint` |
| Call Counter | `registration_entry`, `manager`, `prune` |
| Counter | `server_ca`, `sign`, `jwt_svid` | `spiffe_id` |
| Counter | `server_ca`, `sign`, `x509_ca_svid` | `spiffe_id` |
| Counter | `server_ca`, `sign`, `x509_svid` | `spiffe_id` |
| Call Counter | `svid`, `rotate` |
| Gauge | `started` | `version` |

## SPIRE Agent

| Type | Keys | Labels |
| ---  | --- | --- |
| Call Counter | `agent_svid`, `rotate` |
| Sample | `cache_manager`, `expiring_svids` |
| Sample | `cache_manager`, `outdated_svids` |
| Call Counter | `manager`, `sync`, `fetch_entries_updates` |
| Call Counter | `manager`, `sync`, `fetch_svids_updates` |
| Call Counter | `node`, `attestor`, `new_svid` |
| Counter | `sds_api`, `connections` |
| Counter | `sds_api`, `connections` |
| Counter | `workload_api`, `bundles_update`, `jwt` |
| Counter | `workload_api`, `connections` |
| Counter | `workload_api`, `connections` |
| Sample | `workload_api`, `discovered_selectors` |
| Call Counter | `workload_api`, `fetch_jwt_bundles` | `svid_type` |
| Counter | `workload_api`, `fetch_jwt_bundles` |
| Gauge | `workload_api`, `fetch_jwt_svid`, `ttl` | `spiffe_id` |
| Call Counter | `workload_api`, `fetch_jwt_svid` | `svid_type` |
| Gauge | `workload_api`, `fetch_x509_svid`, `ttl` | `spiffe_id` |
| Call Counter | `workload_api`, `fetch_x509_svid` | `svid_type` |
| Measure Since | `workload_api`, `send_jwt_bundle_latency` |
| Measure Since | `workload_api`, `svid_response_latency`, `fetch` |
| Counter | `workload_api`, `validate_jwt_svids` | `subject`, `audience` |
| Counter | `workload_api`, `validate_jwt_svids` |
| Call Counter | `workload_api`, `workload_attestation` |
| Call Counter | `workload_api`, `workload_attestor` | `attestor` |
| Gauge | `started` | `version` |
