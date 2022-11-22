# Agent plugin: WorkloadAttestor "windows"

The `windows` plugin generates Windows-based selectors for workloads calling the agent.
It does so by opening an access token associated with the workload process. The system is then interrogated to retrieve user and group account information from that access token.

| Configuration            | Description                                                                                                                                                | Default |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `discover_workload_path` | If true, the workload path will be discovered by the plugin and used to provide additional selectors                                                       | false   |
| `workload_size_limit`    | The limit of workload binary sizes when calculating certain selectors (e.g. sha256). If zero, no limit is enforced. If negative, never calculate the hash. | 0       |

## Workload Selectors

| Selector                                    | Value                                                                                                                                                                                                                   |
|---------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `windows:user_sid`                          | The security identifier (SID) that identifies the user running the workload (e.g. `windows:user_sid:S-1-5-21-759542327-988462579-1707944338-1003`)                                                                      |
| `windows:user_name`                         | The user name of the user running the workload (e.g. `windows:user_name:computer-or-domain\myuser`)                                                                                                                     |
| `windows:group_sid:se_group_enabled:true`   | The security identifier (SID) that identifies an enabled group associated with the access token from the workload process (e.g. `windows:group_sid:se_group_enabled:true:S-1-5-21-759542327-988462579-1707944338-1004`) |
| `windows:group_sid:se_group_enabled:false`  | The security identifier (SID) that identifies a not enabled group associated with the access token from the workload process (e.g. `windows:group_sid:se_group_enabled:false:S-1-5-32-544`)                             |
| `windows:group_name:se_group_enabled:true`  | The group name of an enabled group associated with the access token from the workload process (e.g. `windows:group_name:se_group_enabled:true:computer-or-domain\mygroup`)                                              |
| `windows:group_name:se_group_enabled:false` | The group name of a not enabled group associated with the access token from the workload process (e.g. `windows:group_name:se_group_enabled:false:computer-or-domain\mygroup`)                                          |

Workload path enabled selectors (available when configured with `discover_workload_path = true`):

| Selector         | Value                                                                                                                             |
|------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `windows:path`   | The path to the workload binary (e.g. `windows:path:C:\Program Files\nginx\nginx.exe`)                                            |
| `windows:sha256` | The SHA256 digest of the workload binary (e.g. `windows:sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7`) |

Security Considerations:

Malicious workloads could cause the SPIRE agent to do expensive work
calculating a sha256 for large workload binaries, causing a denial-of-service.
Defenses against this are:

- disabling calculation entirely by setting `workload_size_limit` to a negative value
- use `workload_size_limit` to enforce a limit on the binary size the
  plugin is willing to hash. However, the same attack could be performed by spawning a
  bunch of processes under the limit.
  The workload API does not yet support rate limiting, but when it does, this attack can
  be mitigated by using rate limiting in conjunction with non-negative `workload_size_limit`.

### Notes

- An enabled group in a token is a group that has the [SE_GROUP_ENABLED](https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token) attribute.

- User and group account names are expressed using the [down-level logon name format](https://docs.microsoft.com/en-us/windows/win32/secauthn/user-name-formats#down-level-logon-name).

## Configuration

This plugin does not require any configuration setting. It can be added in the following way in the agent configuration file:

```hcl
    WorkloadAttestor "windows" {
    }
```

## Platform support

This plugin is only supported on Windows.
