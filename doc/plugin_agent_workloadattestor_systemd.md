# Agent plugin: WorkloadAttestor "systemd"

The `systemd` plugin generates selectors based on [systemd](https://systemd.io/) unit properties of the workloads calling the agent.

This plugin does not accept any configuration options.

General selectors:

| Selector                | Value                                                                                                                |
|-------------------------|----------------------------------------------------------------------------------------------------------------------|
| `systemd:id`            | The unit Id of the workload (e.g. `systemd:id:nginx.service`)                                                        |
| `systemd:fragment_path` | The unit file path this workload unit was read from (e.g. `systemd:fragment_path:/lib/systemd/system/nginx.service`) |

A sample configuration:

```hcl
    WorkloadAttestor "systemd" {
    }
```

## Platform support

This plugin is only supported on Unix systems.
