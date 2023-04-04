# Agent plugin: WorkloadAttestor "systemd"

The `systemd` plugin generates selectors based on [systemd](https://systemd.io/) unit properties of the workloads calling the agent.

This plugin does not accept any configuration options.

General selectors:

| Selector               | Value                                                                                                               |
|------------------------|---------------------------------------------------------------------------------------------------------------------|
| `systemd:Id`           | The unit Id of the workload (e.g. `systemd:Id:nginx.service`)                                                       |
| `systemd:FragmentPath` | The unit file path this workload unit was read from (e.g. `systemd:FragmentPath:/lib/systemd/system/nginx.service`) |

A sample configuration:

```hcl
    WorkloadAttestor "systemd" {
    }
```

## Platform support

This plugin is only supported on Unix systems.
