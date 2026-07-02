# Server plugin: BundlePublisher "azure_blob"

The `azure_blob` plugin puts the current trust bundle of the server in a designated
Azure Blob Storage container, keeping it updated.

The plugin accepts the following configuration options:

| Configuration        | Description                                                                                                                                                                          | Required                                             | Default               |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|-----------------------|
| storage_account_name | The name of the Azure Storage account.                                                                                                                                               | Yes.                                                 |                       |
| storage_account_key  | The Azure Storage account access key for shared key authentication.                                                                                                                  | Required only when using shared key authentication.  |                       |
| container_name       | The name of the blob container to which the trust bundle is uploaded.                                                                                                                | Yes.                                                 |                       |
| blob_name            | The blob name inside the container.                                                                                                                                                  | Yes.                                                 |                       |
| format               | Format in which the trust bundle is stored, &lt;spiffe &vert; jwks &vert; pem&gt;. See [Supported bundle formats](#supported-bundle-formats) for more details.                       | Yes.                                                 |                       |
| service_endpoint     | The Azure Blob Storage service endpoint.                                                                                                                                             | No.                                                  | blob.core.windows.net |
| tenant_id            | The Azure tenant ID for client secret credential authentication.                                                                                                                     | Required only when using client secret credentials.  |                       |
| app_id               | The Azure application (client) ID for client secret credential authentication.                                                                                                       | Required only when using client secret credentials.  |                       |
| app_secret           | The Azure application client secret for client secret credential authentication.                                                                                                     | Required only when using client secret credentials.  |                       |
| refresh_hint         | Sets the refresh hint for the bundle when using the spiffe format. Specified as string e.g. '10m', '1h'. See [time.ParseDuration](https://pkg.go.dev/time#ParseDuration) for details | No.                                                  |                       |

## Supported bundle formats

The following bundle formats are supported:

### SPIFFE format

The trust bundle is represented as an RFC 7517 compliant JWK Set, with the specific parameters defined in the [SPIFFE Trust Domain and Bundle specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format). Both the JWT authorities and the X.509 authorities are included.

### JWKS format

The trust bundle is encoded as an RFC 7517 compliant JWK Set, omitting SPIFFE-specific parameters. Both the JWT authorities and the X.509 authorities are included.

### PEM format

The trust bundle is formatted using PEM encoding. Only the X.509 authorities are included.

## Authentication

The plugin supports three authentication methods. Only one method may be used at a time; shared key authentication and client secret credentials are mutually exclusive.

### Shared key authentication

When `storage_account_key` is provided, the plugin authenticates using the storage account's access key. This method does not require Azure AD and is useful in environments where Azure AD is not available.

### Client secret credentials

When `tenant_id`, `app_id`, and `app_secret` are all provided, the plugin authenticates using Azure client secret credentials. All three fields must be specified together.

### Default Azure credentials

When neither shared key nor client secret credentials are configured, the plugin uses the [Azure Default Credential](https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication) chain. This supports Managed Identity, environment variables, Azure CLI credentials, and other methods provided by the Azure SDK.

## Required permissions

The authenticated identity must have the `Storage Blob Data Contributor` role (or equivalent permissions to write blobs) on the configured storage account or container.

## Sample configuration using Default Azure Credentials

The following configuration uploads the local trust bundle contents to the `example.org` blob in the `spire-bundle` container within the `mystorageaccount` storage account. Since client secret credentials are not configured, [Default Azure Credentials](https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication) are used.

```hcl
    BundlePublisher "azure_blob" {
        plugin_data {
            storage_account_name = "mystorageaccount"
            container_name = "spire-bundle"
            blob_name = "example.org"
            format = "spiffe"
        }
    }
```

## Sample configuration using shared key authentication

The following configuration uploads the local trust bundle contents to the `example.org` blob in the `spire-bundle` container, authenticating with a storage account access key.

```hcl
    BundlePublisher "azure_blob" {
        plugin_data {
            storage_account_name = "mystorageaccount"
            storage_account_key = "my-storage-account-key"
            container_name = "spire-bundle"
            blob_name = "example.org"
            format = "spiffe"
        }
    }
```

## Sample configuration using client secret credentials

The following configuration uploads the local trust bundle contents to the `example.org` blob in the `spire-bundle` container, authenticating with client secret credentials.

```hcl
    BundlePublisher "azure_blob" {
        plugin_data {
            storage_account_name = "mystorageaccount"
            container_name = "spire-bundle"
            blob_name = "example.org"
            format = "spiffe"
            tenant_id = "my-tenant-id"
            app_id = "my-app-id"
            app_secret = "my-app-secret"
        }
    }
```
