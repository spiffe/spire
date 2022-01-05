# Agent plugin: SVIDStore "disk"

The `disk` plugin stores in disk the resulting X509-SVIDs of the entries that the agent is entitled to. 

### Format

The plugin stores the SVID in three different PEM encoded files: one for the certificate chain, one for the certificate key and one for the trust domain bundle. The file paths are specified through [selectors](#selectors).

_Note: federated bundles are not stored by this plugin._

### Configuration

| Configuration        | Description | DEFAULT        | 
| -------------------- | ----------- | -------------- | 
| directory | Base directory that is used to store the SVIDs. All stored files are under this path. |  | 

A sample configuration:

```
    SVIDStore "disk" {
       plugin_data {
           directory = "/path/to/svids"
       }
    }
```

### Selectors

Selectors are used on `storable` entries to describre metadata that is needed by the `disk` plugin in order to store the SVIDs on disk. In case that a required selector is not provided, the plugin will return an error at execution time.

| Selector                      | Example                                    | Required | Description                                    |
| ----------------------------- | ------------------------------------------ | -------- | --------------------------------------------   |
| `disk:certchainfile`      | `disk:certchainfile:tls.crt`   | x        | The file path relative to the base directory where the SVID certificate chain will be stored. Must be in the same directory as `keyfile` and `bundlefile`. |
| `disk:keyfile` | `disk:keyfile:key.crt` | x        | The file path relative to the base directory where the SVID certificate key will be stored. Must be in the same directory as `certchainfile` and `bundlefile`. |
| `disk:bundlefile`     | `disk:bundlefile:ca.crt` | x        | The file path relative to the base directory where the CA certificates belonging to the Trust Domain of the SVID will be stored. Must be in the same directory as `certchainfile` and `keyfile`. |
| `disk:group`     | `disk:group:my-workload` | x (if `gid` is not specified)       | The group name that is set to the files written to disk. If set, `gid` cannot be specified. |
| `disk:gid`     | `disk:group:my-workload` | x (if `group` is not specified)       | The group ID that is set to the files written to disk. If set, `group` cannot be specified. |

### Required permissions

In order to be able to set proper ownership of the written files, this plugin requires that the user that runs SPIRE Agent is a member of the group specified through the `disk:group` or `disk:gid` selectors.
