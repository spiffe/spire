# Audit log

The SPIRE Server can be configured to emit audit logs using [audit_log_enabled](spire_server.md#server-configuration-file) that are sent into the same file as regular logs.

## Fields

Each entry contains fields related with provided `request` to each endpoint, but additionally contains `audit log` specific fields that provides aditional information

| Key | Description | Values |
| --- | ----------- | ------ |
| type  | constant that is used to identify that current entry is an audit log | audit |
| request_id | uuid that identifies current call, it is useful for `Batch` endpoints that can emit multiple audit logs, one per each operation that is done. | |
| status | Describe if call was successfull or not | [error, success] | 
| status_code | in case of error contains `gRPC` status code  | |
| status_message | in case of error contains error returned to caller | |

Aditionally provides fields to to identify `caller`

UDS:
> **_NOTE:_**  In order to enable audit logs in K8S for UDS calls `hostPID: true` is required on SPIRE Server node.

| Key | Description                |
| ----------- | ------------------ |
| caller_uid  | caller user ID     |
| caller_gid  | caller group ID    |
| caller_path | caller binary path |

TLS:
| Key | Description                                            | 
| --- | ------------------------------------------------------ | 
| caller_addr | caller IP address                              |
| caller_id   | SPIFFE ID from certificate presented by caller |
