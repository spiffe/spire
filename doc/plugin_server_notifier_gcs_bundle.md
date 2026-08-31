# Server plugin: Notifier "gcs_bundle"

> [!WARNING]
> The Notifier plugin type is deprecated and will be removed in a future
> release. Use the [`gcp_cloudstorage` BundlePublisher](/doc/plugin_server_bundlepublisher_gcp_cloudstorage.md)
> plugin instead. See [Migrating to the `gcp_cloudstorage` BundlePublisher](#migrating-to-the-gcp_cloudstorage-bundlepublisher).

The `gcs_bundle` plugin responds to bundle loaded/updated events by fetching and
pushing the latest root CA certificates from the trust bundle to an object in
Google Cloud Storage.

The certificates in the object can be used to bootstrap SPIRE agents.

The plugin accepts the following configuration options:

| Configuration          | Description                                  | Default |
|------------------------|----------------------------------------------|---------|
| `bucket`               | The bucket containing the object             |         |
| `object_path`          | The path to the object within the bucket     |         |
| `service_account_file` | Path to the service account credentials file |         |

## Authenticating with Google Cloud Storage

The plugin authenticates with Google Cloud Storage using the mechanisms
described in the Google Cloud [authentication documentation](https://cloud.google.com/docs/authentication/production).
Specifically, service account credentials are obtained using a file path
configured via `service_account_file`, or the plugin uses Application Default
Credentials available in the environment the SPIRE server is running in.

## Sample configurations

### Authenticate Via Application Default Credentials

The following configuration uploads bundle contents to the `spire-bundle.pem`
object in the `my-bucket` bucket. The bundle is uploaded using Application
Default Credentials available in the environment SPIRE server is running in.

```hcl
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

```hcl
    Notifier "gcs_bundle" {
        plugin_data {
            bucket = "my-bucket"
            object_path = "spire-bundle.pem"
            service_account_file = "/path/to/service/account/file"
        }
    }
```

## Migrating to the `gcp_cloudstorage` BundlePublisher

The [`gcp_cloudstorage` BundlePublisher](/doc/plugin_server_bundlepublisher_gcp_cloudstorage.md)
uploads the trust bundle to a Google Cloud Storage object as well, and
authenticates the same way, but the configuration options are named differently
and the bundle format has to be set explicitly.

| `gcs_bundle`           | `gcp_cloudstorage`     |
|------------------------|------------------------|
| `bucket`               | `bucket_name`          |
| `object_path`          | `object_name`          |
| `service_account_file` | `service_account_file` |

Set `format` to `pem` to keep the object contents unchanged, since `gcs_bundle`
uploads the X.509 authorities PEM encoded. The `spiffe` and `jwks` formats
include the JWT authorities as well, so switching to one of them changes what
consumers of the object read.

The following configuration is equivalent to the first sample configuration
above:

```hcl
    BundlePublisher "gcp_cloudstorage" {
        plugin_data {
            bucket_name = "my-bucket"
            object_name = "spire-bundle.pem"
            format = "pem"
        }
    }
```
