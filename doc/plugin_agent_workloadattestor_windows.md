# Agent plugin: WorkloadAttestor "windows"

The `windows` plugin generates Windows-based selectors for workloads calling the agent.
It does so by opening an access token associated with the workload process. The system is then interrogated to retrieve user and group account information from that access token.

### Workload Selectors

| Selector | Value |
| -------- | ----- |
| `windows:user_sid` | The security identifier (SID) that identifies the user running the workload (e.g. `windows:user_sid:S-1-5-21-759542327-988462579-1707944338-1003`) |
| `windows:user_name` | The user name of the user running the workload (e.g. `windows:user_name:computer-or-domain\myuser`) |
| `windows:group_sid:se_group_enabled:true` | The security identifier (SID) that identifies an enabled group associated with the access token from the workload process (e.g. `windows:group_sid:se_group_enabled:true:S-1-5-21-759542327-988462579-1707944338-1004`) |
| `windows:group_sid:se_group_enabled:false` | The security identifier (SID) that identifies a not enabled group associated with the access token from the workload process (e.g. `windows:group_sid:se_group_enabled:false:S-1-5-32-544`) |
| `windows:group_name:se_group_enabled:true` | The group name of an enabled group associated with the access token from the workload process (e.g. `windows:group_name:se_group_enabled:true:computer-or-domain\mygroup`) |
| `windows:group_name:se_group_enabled:false` | The group name of a not enabled group associated with the access token from the workload process (e.g. `windows:group_name:se_group_enabled:false:computer-or-domain\mygroup`) |

#### Notes
- An enabled group in a token is a group that has the [SE_GROUP_ENABLED](https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token) attribute.

- User and group account names are expressed using the [down-level logon name format](https://docs.microsoft.com/en-us/windows/win32/secauthn/user-name-formats#down-level-logon-name).

### Configuration

This plugin does not require any configuration setting. It can be added in the following way in the agent configuration file:

```
	WorkloadAttestor "windows" {
	}
```

### Platform support

This plugin is only supported on Windows.
