# Server plugin: KeyManager "disk"

The `disk` key manager maintains a set of private keys that are persisted to
disk.

The plugin accepts the following configuration options:

| Configuration        | Description                                                                                                                                  |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| keys_path            | Path to the keys file on disk                                                                                                                 |
| key_identifier_file  | A path (local to this server) used to persist an auto-generated, per-server identifier. Required with `shared_keys` unless `key_identifier_value` is set. |
| key_identifier_value | An explicit, stable per-server identifier. Required with `shared_keys` unless `key_identifier_file` is set.                                   |
| shared_keys          | Configuration for shared keys                                                                                                                 |

 The `shared_keys` configuration block has the following members:

| Configuration       | Description                                                                                                                           |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| crypto_key_template | A golang text/template (with [Sprig v3](http://masterminds.github.io/sprig/) functions available) used to derive the ID JWT keys are stored under in the file. `{{ .TrustDomain }}` and `{{ .KeyID }}` are available. The template must vary with `{{ .KeyID }}`. |

> **Note**: Only JWT signing keys are shared between servers. X509 CA and WIT keys remain per-server, namespaced by the server identifier, so each server keeps its own. This is why a `key_identifier_file` or `key_identifier_value` is required when `shared_keys` is enabled.

> **Note**: Any existing keys cannot be used after turning on the shared keys feature. Additionally, using the `disk` key manager with the `shared_keys` feature requires a network-accessible shared volume (e.g., NFS v4, or a cloud-managed network filesystem) mounted on every SPIRE server instance that participates in key sharing. File-lock contention on the shared volume scales with server count and rotation cadence; prefer a low-latency mount.

A sample configuration:

```hcl
    KeyManager "disk" {
        plugin_data = {
            keys_path = "/opt/spire/data/server/keys.json"
            key_identifier_file = "/opt/spire/data/server/server-id"
            shared_keys = {
                crypto_key_template = "{{ .TrustDomain }}-{{ .KeyID }}"
            }
        }
    }
```
