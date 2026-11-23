# Logging

SPIRE Server and Agent emit structured logs in text or JSON format. Use `log_level`, `log_format`, and `log_file` in the [server](spire_server.md#server-configuration-file) or [agent](spire_agent.md#agent-configuration-file) configuration to control their verbosity, format, and destination.

## Audit logging

SPIRE Server can be configured to emit audit logs through the [audit_log_enabled](spire_server.md#server-configuration-file) configuration. Audit logs are sent to the same output as regular logs.

When audit logging is enabled, [audit_log_exclude_agent_sync](spire_server.md#server-configuration-file) can omit successful `GetBundle`, `GetFederatedBundle`, `GetAuthorizedEntries`, and `SyncAuthorizedEntries` RPC audit records regardless of caller identity. Error audit records are retained.

### Fields

Each entry contains fields related with the provided request to each endpoint. It also contains audit log specific fields that provide additional information.

| Key            | Description                                                                                                                                        | Values           |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------|------------------|
| type           | Constant value that is used to identify that the current entry is an audit log.                                                                    | audit            |
| request_id     | A uuid that identifies the current call. It is useful for batch operations that can emit multiple audit logs, one per each operation that is done. |                  |
| status         | Indicates if the call was successful or not.                                                                                                       | [error, success] |
| status_code    | In case of an error, contains the gRPC status code.                                                                                                |                  |
| status_message | In case of an error, contains the error returned to the caller.                                                                                    |                  |

The following fields are provided to identify the caller.

#### Endpoints listening on UDS

> **_NOTE:_**  In order to enable audit log in Kubernetes for calls done on UDS endpoints, `hostPID: true` is required in the SPIRE Server node.

| Key         | Description              |
|-------------|--------------------------|
| caller_uid  | Caller user ID.          |
| caller_gid  | Caller group ID.         |
| caller_path | Caller binary file path. |

#### Endpoints listening on TLS ports

| Key         | Description                                                                   |
|-------------|-------------------------------------------------------------------------------|
| caller_addr | Caller IP address.                                                            |
| caller_id   | SPIFFE ID extracted from the X.509 certificate presented by the caller.       |

## Alert markers

Some log records include fields identifying conditions that may require operator action. These markers make the records easier to find and route in log monitoring systems:

| Field | Meaning |
| --- | --- |
| `alert` | Set to `true` on records marked for operator attention. |
| `alert_type` | Identifies the category of the condition. |

Filter on `alert=true` to find marked records, and use `alert_type` to distinguish the conditions you want to monitor. The fields are present in both text and JSON output, and normal `log_level` filtering applies.

The following alert types are currently emitted:

| Alert type | Component | Meaning |
| --- | --- | --- |
| `deprecated_config` | Server and Agent | A deprecated configuration setting or behavior is in use. See [upgrade guidance](upgrading.md#configuration-and-behavior-compatibility). |
| `deprecated_service` | Server and Agent | A plugin implements a deprecated service interface. See [plugin interface compatibility](upgrading.md#interface-compatibility). |
| `shortened_lifetime` | Server | Requested credential lifetimes may be shortened, or CA rotation is constrained by usable certificate lifetimes. See [CA and SVID lifetimes](spire_server.md#ca-and-svid-lifetimes). |
