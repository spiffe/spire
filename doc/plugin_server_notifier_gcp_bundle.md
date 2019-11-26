# Server plugin: Notifier "gcs_bundle"

The `gcs_bundle` plugin responds to bundle loaded/updated events by fetching and
pushing the latest root CA certificates from the trust bundle to an object in
Google Cloud Storage.

The certificates in the object can be used to bootstrap SPIRE agents.

The plugin accepts the following configuration options:

| Configuration          | Description                                  | Default         |
| ---------------------- | -------------------------------------------- | --------------- |
| `bucket`               | The bucket containing the object             |                 |
| `object_path`          | The path to the object within the bucket     |                 |
| `service_account_file` | Path to the service account credentials file |                 |

## Authenticating with Google Cloud Storage

The plugin authenticates with Google Cloud Storage using the mechanisms
described in [Authentication Setup Docs](https://cloud.google.com/docs/authentication/production).
Specifically, service account credentials are obtained using a file path
configured via `service_account_file`, or the plugin uses Application Default
Credentials available in the environment the SPIRE server is running in.

## Sample configurations

### Authenticate Via Application Default Credentials

The following configuration uploads bundle contents to the `spire-bundle.pem`
object in the `my-bucket` bucket. The bundle is uploaded using Application
Default Credentials available in the environment SPIRE server is running in.

```
    Notifier "gcs_bundle" {
        plugin_data {
            bucket = "my-bucket"
            object_path = "spire-bundle.pem"
        }
    }
```

### Authenticate Via Explicit Service Account Credentials

The following configuration uploads bundle contents to the `spire-bundle.pem`
object in the `my-bucket` bucket. The bundle is uploaded using Service Account
credentials found in the `/path/to/service/account/file` file.

```
    Notifier "gcs_bundle" {
        plugin_data {
            bucket = "my-bucket"
            object_path = "spire-bundle.pem"
            service_account_file = "/path/to/service/account/file"
        }
    }
```
