# Server plugin: KeyManager "disk"

The `disk` key manager maintains a set of private keys that are persisted to
disk.

The plugin accepts the following configuration options:

| Configuration | Description                   |
|---------------|-------------------------------|
| keys_path     | Path to the keys file on disk |
| shared_keys   | Configuration for shared keys |

 The `shared_keys` configuration block has the following members:

| Configuration       | Description                                                                                                                           |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| crypto_key_template | A golang text/template used to derive the ID keys are stored under in the file. `{{ .TrustDomain }}` and `{{ .KeyID }}` are available. |

> **Note**: Any existing keys cannot be used after turning on the shared keys feature. Additionally, using the `disk` key manager with the `shared_keys` feature requires a volume mount be shared between the SPIRE server instances sharing the key.

A sample configuration:

```hcl
    KeyManager "disk" {
        plugin_data = {
            keys_path = "/opt/spire/data/server/keys.json"
            shared_keys = {
                crypto_key_template = "{{ .TrustDomain }}-key"
            }
        }
    }
```
