# Server plugin: BundlePublisher "gcp_cloudstorage"

The `gcp_cloudstorage` plugin puts the current trust bundle of the server in a designated
Google Cloud Storage bucket, keeping it updated.

The plugin accepts the following configuration options:

| Configuration        | Description                                                                                                                                                    | Required | Default                                                         |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|-----------------------------------------------------------------|
| service_account_file | Path to the service account file used to authenticate with the Cloud Storage API.                                                                              | No.      | Value of `GOOGLE_APPLICATION_CREDENTIALS` environment variable. |
| bucket_name          | The Google Cloud Storage bucket name to which the trust bundle is uploaded.                                                                                    | Yes.     |                                                                 |
| object_name          | The object name inside the bucket.                                                                                                                             | Yes.     |                                                                 |
| format               | Format in which the trust bundle is stored, &lt;spiffe &vert; jwks &vert; pem&gt;. See [Supported bundle formats](#supported-bundle-formats) for more details. | Yes.     |                                                                 |

## Supported bundle formats

The following bundle formats are supported:

### SPIFFE format

The trust bundle is represented as an RFC 7517 compliant JWK Set, with the specific parameters defined in the [SPIFFE Trust Domain and Bundle specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format). Both the JWT authorities and the X.509 authorities are included.

### JWKS format

The trust bundle is encoded as an RFC 7517 compliant JWK Set, omitting SPIFFE-specific parameters. Both the JWT authorities and the X.509 authorities are included.

### PEM format

The trust bundle is formatted using PEM encoding. Only the X.509 authorities are included.

## Required permissions

The plugin requires the following IAM permissions be granted to the authenticated service account in the configured bucket:

```text
storage.objects.create
storage.objects.delete
```

The `storage.objects.delete` permission is required to overwrite the object when the bundle is updated.

## Sample configuration using Application Default Credentials

The following configuration uploads the local trust bundle contents to the `example.org` object in the `spire-bundle` bucket. Since `service_account_file` is not configured, [Application Default Credentials](https://cloud.google.com/docs/authentication/client-libraries#adc) are used.

```hcl
    BundlePublisher "gcp_cloudstorage" {
        plugin_data {
            bucket = "spire-bundle"
            object_name = "example.org"
            format = "spiffe"
        }
    }
```

## Sample configuration using service account file

The following configuration uploads the local trust bundle contents to the `example.org` object in the `spire-bundle` bucket. Since `service_account_file` is configured, authentication to the Cloud Storage API is done with the given service account file.

```hcl
    BundlePublisher "gcp_cloudstorage" {
        plugin_data {
            service_account_file = "/path/to/service/account/file"
            bucket = "spire-bundle"
            object_name = "example.org"
            format = "spiffe"
        }
    }
```
