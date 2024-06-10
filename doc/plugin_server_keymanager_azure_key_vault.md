# Server plugin: KeyManager "azure_key_vault"

The `azure_key_vault` key manager plugin leverages the Microsoft Azure Key Vault
Service to create, maintain, and rotate key pairs, signing SVIDs as needed. No
Microsoft Azure principal can view or export the raw cryptographic key material
represented by a key. Instead, Key Vault accesses the key material on behalf of
SPIRE.

## Configuration

The plugin accepts the following configuration options:

| Key                  | Type    | Required                                    | Description                                                                                                                                                      | Default |
|----------------------|---------|---------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| key_identifier_file  | string  | Required if key_identifier_value is not set | A file path location where information about generated keys will be persisted. See "[Management of keys](#management-of-keys)" for more information.             | ""      |
| key_identifier_value | string  | Required if key_identifier_file is not set  | A static identifier for the SPIRE server instance (used instead of `key_identifier_file`).                                                                       | ""      |
| key_vault_uri        | string  | Yes                                         | The Key Vault URI where the keys managed by this plugin reside.                                                                                                  | ""      |
| subscription_id      | string  | [Optional](#authenticating-to-azure)        | The subscription id.                                                                                                                                             | ""      |
| app_id               | string  | [Optional](#authenticating-to-azure)        | The application id.                                                                                                                                              | ""      |
| app_secret           | string  | [Optional](#authenticating-to-azure)        | The application secret.                                                                                                                                          | ""      |
| tenant_id            | string  | [Optional](#authenticating-to-azure)        | The tenant id.                                                                                                                                                   | ""      |

### Authenticating to Azure

By default, the plugin will attempt to use the application default credential by
using the [DefaultAzureCredential API](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#section-readme).
The `DefaultAzureCredential API` attempts to authenticate via the following mechanisms in order -
environment variables, Workload Identity, and Managed Identity; stopping when once succeeds.
When using Workload Identity or Managed Identity, the plugin must be able to fetch the credential for the configured
tenant ID, otherwise the authentication to Key Vault will fail.

Alternatively, the plugin can be configured to use static credentials for an application
registered within the tenant (`subscription_id`, `app_id`, and `app_secret`).

### Use of key versions

In Key Vault, the cryptographic key material that is used to sign data is stored
in a key version. A key can have zero or more key versions.

For each SPIRE Key ID that the server manages, this plugin maintains a Key.
When a key is rotated, a new version is added to the Key.

Note that Azure does not support deleting individual key versions, instead, the key itself is deleted by the plugin
when it's no longer being used by a server in the trust domain the server belongs to.

### Management of keys

The plugin assigns [tags](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details#key-tags) to the
keys that it manages in order to keep track of them. All the tags are named with the `spire-` prefix.
Users don't need to interact with the labels managed by the plugin. The
following table is provided for informational purposes only:

| Label           | Description                                                                                                                             |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| spire-server-td | A string representing the trust domain name of the server.                                                                              |
| spire-server-id | An identifier that is unique to the server. This is handled by either the `key_identifier_file` or `key_identifier_value` configurable. |

The plugin needs a way to identify the specific server instance where it's
running. For that, either the `key_identifier_file` or `key_identifier_value`
setting must be used. Setting a _Key Identifier File_ instructs the plugin to
manage the identifier of the server automatically, storing the server ID in the
specified file. This method should be appropriate for most situations.
If a _Key Identifier File_ is configured and the file is not found during server
startup, the file is recreated with a new auto-generated server ID.
Consequently, if the file is lost, the plugin will not be able to identify keys
that it has previously managed and will recreate new keys on demand.

If you need more control over the identifier that's used for the server, the
`key_identifier_value` setting can be used to specify a
static identifier for the server instance. This setting is appropriate in situations
where a key identifier file can't be persisted.

The plugin attempts to detect and delete stale keys. To facilitate stale
keys detection, the plugin actively updates the `Updated` field of all keys managed by the server every 6 hours.
Within the Key Vault the plugin is configured to use (`key_vaut_uri`), the plugin periodically scans the keys looking
for active keys within the trust domain that have their `Updated` field value older than two weeks and deletes them.

### Required permissions

The identity used need the following permissions on the Key Vault it's configured to use:

Key Management Operations

```text
Get
List
Update
Create
Delete
```

Cryptographic Operations

```text
Sign
Verify
```

## Supported Key Types

The plugin supports all the key types supported by SPIRE: `rsa-2048`,
`rsa-4096`, `ec-p256`, and `ec-p384`.
