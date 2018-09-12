# Agent plugin: WorkloadAttestor "unix"

The `unix` plugin generates unix-based selectors for workloads calling the agent.

This plugin does not accept any configuration options.

| Selector | Value |
| -------- | ----- |
| unix:uid | The user ID of the workload (e.g. `unix:uid:1000`) |
| unix:user | The user name of the workload (e.g. `unix:user:nginx`) |
| unix:gid | The group ID of the workload (e.g. `unix:gid:1000`) |
| unix:group | The group name of the workload (e.g. `unix:gid:www-data`) |
