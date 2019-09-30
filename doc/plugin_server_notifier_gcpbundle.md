# Server plugin: Notifier "gcpbundle"

The `gcpbundle` plugin responds to bundle loaded/updated events by fetching and
pushing the latest root CA certificates from the trust bundle to an object in
Google Cloud Storage.

The certificates in the object can be used to bootstrap SPIRE agents.

In HA, multiple SPIRE servers will be pushing bundle contents to the object.
The plugin handles conflict resolution by implementing a read-modify-write
cycle to ensure the object contains the latest bundle contents.

The plugin accepts the following configuration options:

| Configuration          | Description                                 | Default         |
| ---------------------- | ------------------------------------------- | --------------- |
| `bucket`               | The bucket containing the object            |                 |
| `object_path`          | The path to the object within the bucket    |                 |
| `service_account_file` | Path to the service account file used to authenticate with Google Cloud Storage | |

## Sample configurations

### Default In-Cluster

The following configuration pushes bundle contents from an in-cluster SPIRE
server to the `spire-bundle.pem` object in the `my-bucket` bucket.

```
    Notifier "gcpbundle" {
        plugin_data {
            bucket = "my-bucket"
            object_path = "spire-bundle.pem"
        }
    }
```

### Out-Of-Cluster

The following configuration pushes bundle contents from an out-of-cluster SPIRE
server to the `spire-bundle.pem` object in the `my-bucket` bucket using
the service account credentials found in the `/path/to/service/account/file` file.

```
    Notifier "gcpbundle" {
        plugin_data {
            bucket = "my-bucket"
            object_path = "spire-bundle.pem"
            service_account_file = "/path/to/service/account/file"
        }
    }
```
