# Agent plugin: SVIDStore "disk"

The `disk` plugin stores in disk the resulting X509-SVIDs of the entries that the agent is entitled to. 

### Format

The plugin stores the SVID in three different PEM encoded files: one for the certificate chain, one for the certificate key and one for the trust domain bundle. The file names can be specified through [selectors](#selectors).

_Note: federated bundles are not stored by this plugin._

### Configuration

| Configuration        | Description | DEFAULT        | 
| -------------------- | ----------- | -------------- | 
| base_dir | Base directory that is used to store the SVIDs. All stored files are under this path. |  | 

A sample configuration:

```
    SVIDStore "disk" {
       plugin_data {
           base_dir = "/path/to/svids"
       }
    }
```

### Selectors

Selectors are used on `storable` entries to describre metadata that is needed by the `disk` plugin in order to store the SVIDs on disk. In case that a required selector is not provided, the plugin will return an error at execution time.

| Selector                      | Example                                    | Required | Description                                    |
| ----------------------------- | ------------------------------------------ | -------- | --------------------------------------------   |
| `disk:sub_dir`     | `disk:sub_dir:my-workload-dir` | x | The subdirectory under the base directory of the plugin that will hold all the stored files. |
| `disk:cert_chain_file`      | `disk:cert_chain_file:tls.crt`   | | File name where the SVID certificate chain will be stored. If not specified, the name `chain.crt` is used as default. |
| `disk:key_file` | `disk:key_file:tls.key` | | The file name where the SVID certificate key will be stored. If not specified, the name `key.key` is used as default. |
| `disk:bundle_file`     | `disk:bundle_file:ca.crt` | | The file name where the CA certificates belonging to the Trust Domain of the SVID will be stored. If not specified, the name `bundle.crt` is used as default. |
| `disk:group_id`     | `disk:group_id:1005` | x (if `group_id` is not specified)       | The group name that is set to the files written to disk. If set, `group_name` cannot be specified. |
| `disk:group_name`     | `disk:group_name:my-workload` | x (if `group_id` is not specified)       | The group name that is set to the files written to disk. If set, `group_id` cannot be specified. |

### Required permissions

In order to be able to set proper ownership of the written files, this plugin requires that the user that runs SPIRE Agent is a member of the group specified through the `disk:group_id` or `disk:group_name` selectors.
