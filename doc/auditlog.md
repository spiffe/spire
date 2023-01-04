# Audit log

SPIRE Server can be configured to emit audit logs through the [audit_log_enabled](spire_server.md#server-configuration-file) configuration. Audit logs are sent to the same output as regular logs.

## Fields

Each entry contains fields related with the provided request to each endpoint. It also contains audit log specific fields that provide additional information.

| Key            | Description                                                                                                                                        | Values           |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------|------------------|
| type           | Constant value that is used to identify that the current entry is an audit log.                                                                    | audit            |
| request_id     | A uuid that identifies the current call. It is useful for batch operations that can emit multiple audit logs, one per each operation that is done. |                  |
| status         | Indicates if the call was successful or not.                                                                                                       | [error, success] |
| status_code    | In case of an error, contains the gRPC status code.                                                                                                |                  |
| status_message | In case of an error, contains the error returned to the caller.                                                                                    |                  |

The following fields are provided to identify the caller.

### Endpoints listening on UDS

> **_NOTE:_**  In order to enable audit log in Kubernetes for calls done on UDS endpoints, `hostPID: true` is required in the SPIRE Server node.

| Key         | Description              |
|-------------|--------------------------|
| caller_uid  | Caller user ID.          |
| caller_gid  | Caller group ID.         |
| caller_path | Caller binary file path. |

### Endpoints listening on TLS ports

| Key         | Description                                                                   |
|-------------|-------------------------------------------------------------------------------|
| caller_addr | Caller IP address.                                                            |
| caller_id   | SPIFFE ID extracted from the X.509 certificate presented by the caller.       |
