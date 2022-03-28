# Agent plugin: WorkloadAttestor "windows"

The `windows` plugin generates Windows-based selectors for workloads calling the agent.

General selectors:

| Selector | Value |
| -------- | ----- |
| `windows:user_sid` | The security identifier (SID) that identifies the user running the workload (e.g. `windows:user_sid:S-1-5-21-759542327-988462579-1707944338-1003`) |
| `windows:user` | The user name of the user running the workload (e.g. `windows:user:myuser`) |
| `windows:group_sid` | The security identifier (SID) that identifies a group of the workload (e.g. `windows:group_sid:S-1-5-32-544`) |
| `windows:group` | The group name of the workload (e.g. `windows:group:mygroup`) |

A sample configuration:

```
	WorkloadAttestor "windows" {
		plugin_data {
		}
	}
```
