# Server plugin: KeyManager "disk"

The `disk` key manager maintains a set of private keys that are persisted to
disk.

The plugin accepts the following configuration options:

| Configuration  | Description                           |
| -------------- | ------------------------------------- |
| keys_path      | Path to the keys file on disk         |

A sample configuration:

```
	KeyManager "disk" {
		plugin_data = {
			keys_path = "/opt/spire/data/server/keys.json"
		}
	}
```
