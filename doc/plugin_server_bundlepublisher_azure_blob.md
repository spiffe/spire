# Server plugin: BundlePublisher "azure_blob"

The `azure_blob` plugin puts the current trust bundle of the server in a designated
Azure Blob Storage container, keeping it updated.

The plugin accepts the following configuration options:

| Configuration        | Description                                                                                                                                                                          | Required                                             | Default               |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|-----------------------|
| storage_account_name | The name of the Azure Storage account.                                                                                                                                               | Yes.                                                 |                       |
| storage_account_key  | The base64-encoded access key for the Azure Storage account. Used for shared key authentication (found in the Azure Portal, **Access keys**).                                        | Required only when using shared key authentication.  |                       |
| container_name       | The name of the blob container to which the trust bundle is uploaded.                                                                                                                | Yes.                                                 |                       |
| blob_name            | The blob name inside the container.                                                                                                                                                  | Yes.                                                 |                       |
| format               | Format in which the trust bundle is stored, &lt;spiffe &vert; jwks &vert; pem&gt;. See [Supported bundle formats](#supported-bundle-formats) for more details.                       | Yes.                                                 |                       |
| service_endpoint     | The Azure Blob Storage service endpoint.                                                                                                                                             | No.                                                  | blob.core.windows.net |
| tenant_id            | The Azure tenant ID for client secret credential authentication.                                                                                                                     | Required only when using client secret credentials.  |                       |
| app_id               | The Azure application (client) ID for client secret credential authentication.                                                                                                       | Required only when using client secret credentials.  |                       |
| app_secret           | The Azure application client secret for client secret credential authentication.                                                                                                     | Required only when using client secret credentials.  |                       |
| refresh_hint         | Sets the refresh hint for the bundle when using the spiffe format. Specified as string e.g. '10m', '1h'. See [time.ParseDuration](https://pkg.go.dev/time#ParseDuration) for details | No.                                                  |                       |
| oidc_compatible      | When `true`, the `jwks` format is the JWK Set served by the OIDC Discovery Provider: only the JWT authorities, each with its `alg` and `use`. See [JWKS format](#jwks-format).       | No.                                                  | false                 |

## Supported bundle formats

The following bundle formats are supported:

### SPIFFE format

The trust bundle is represented as an RFC 7517 compliant JWK Set, with the specific parameters defined in the [SPIFFE Trust Domain and Bundle specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format). Both the JWT authorities and the X.509 authorities are included.

### JWKS format

The trust bundle is encoded as an RFC 7517 compliant JWK Set, omitting SPIFFE-specific parameters. Both the JWT authorities and the X.509 authorities are included.

When `oidc_compatible` is `true`, the JWK Set only includes the JWT authorities, so that it can be used by OIDC relying parties to verify JWT-SVIDs. It has the same keys, with the same members, as the document served on the keys endpoint of the [OIDC Discovery Provider](../support/oidc-discovery-provider/README.md) with `set_key_use` enabled: the X.509 authorities are left out, and every key has its `kid`, its `use` parameter set to `sig` and its `alg` parameter (`RS256` for RSA keys of 2048 bits or more, `ES256` for P-256 keys and `ES384` for P-384 keys). When the bundle has no JWT authorities, an empty set (`{"keys":[]}`) is published, whereas the provider serves no document. A key with no algorithm in that list, such as an RSA key under 2048 bits, is published without `alg`, as the provider does, and a warning is logged. Publishing fails if the key of a JWT authority cannot be parsed. This option can only be used with the `jwks` format.

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
