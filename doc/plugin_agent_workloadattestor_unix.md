# Agent plugin: WorkloadAttestor "unix"

The `unix` plugin generates unix-based selectors for workloads calling the agent.

| Configuration | Description | Default |
| ------------- | ----------- | ------- |
| `discover_workload_path` | If true, the workload path will be discovered by the plugin and used to provide additional selectors | false |

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
| `unix:group` | The group name of the workload (e.g. `unix:gid:www-data`) |

Workload path enabled selectors (available when configured with `discover_workload_path = true`):

| Selector | Value |
| -------- | ----- |
| `unix:path` | The path to the workload binary (e.g. `unix:path:/usr/bin/nginx`) |
| `unix:sha256` | The SHA256 digest of the workload binary (e.g. `unix:sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7`) |
