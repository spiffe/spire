# Agent plugin: WorkloadAttestor "unix"

The `unix` plugin generates unix-based selectors for workloads calling the agent.

| Configuration | Description | Default |
| ------------- | ----------- | ------- |
| `discover_workload_path` | If true, the workload path will be discovered by the plugin and used to provide additional selectors | false |
| `workload_size_limit` | The limit of workload binary sizes when calculating certain selectors (e.g. sha256). If zero, no limit is enforced. If negative, never calculate the hash. | 0 |

If configured with `discover_workload_path = true`, the plugin will discover
the workload path to provide additional selectors. If the plugin cannot
discover the workload path or gather selectors based on the path, it will fail
the attestation attempt. Discovering the workload path requires the agent to
have _sufficient_ platform-specific permissions. For example, on Linux, the
agent would need to be able to read `/proc/<WORKLOAD PID>/exe`, likely
requiring the agent to either run as root or the same user as the workload.
Care must be taken to only enable this option if the agent will be run with
sufficient permissions.

General selectors:

| Selector | Value |
| -------- | ----- |
| `unix:uid` | The user ID of the workload (e.g. `unix:uid:1000`) |
| `unix:user` | The user name of the workload (e.g. `unix:user:nginx`) |
| `unix:gid` | The group ID of the workload (e.g. `unix:gid:1000`) |
| `unix:group` | The group name of the workload (e.g. `unix:group:www-data`) |

Workload path enabled selectors (available when configured with `discover_workload_path = true`):

| Selector | Value |
| -------- | ----- |
| `unix:path` | The path to the workload binary (e.g. `unix:path:/usr/bin/nginx`) |
| `unix:sha256` | The SHA256 digest of the workload binary (e.g. `unix:sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7`) |

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

A sample configuration:

```
	WorkloadAttestor "unix" {
		plugin_data {
		}
	}
```
