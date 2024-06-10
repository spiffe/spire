# Server plugin: KeyManager "gcp_kms"

The `gcp_kms` key manager plugin leverages the Google Cloud Key Management
Service to create, maintain, and rotate key pairs, signing SVIDs as needed. No
Google Cloud principal can view or export the raw cryptographic key material
represented by a key. Instead, Cloud KMS accesses the key material on behalf of
SPIRE.

## Configuration

The plugin accepts the following configuration options:

| Key                  | Type   | Required                                    | Description                                                                                                                                                                                    | Default                                                         |
|----------------------|--------|---------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| key_policy_file      | string | no                                          | A file path location to a custom [IAM Policy (v3)](https://cloud.google.com/pubsub/docs/reference/rpc/google.iam.v1#google.iam.v1.Policy) in JSON format to be attached to created CryptoKeys. | ""                                                              |
| key_identifier_file  | string | Required if key_identifier_value is not set | A file path location where key metadata used by the plugin will be persisted. See "[Management of keys](#management-of-keys)" for more information.                                            | ""                                                              |
| key_identifier_value | string | Required if key_identifier_file is not set  | A static identifier for the SPIRE server instance (used instead of `key_identifier_file`)                                                                                                        | ""                                                              |
| key_ring             | string | yes                                         | Resource ID of the key ring where the keys managed by this plugin reside, in the format projects/\*/locations/\*/keyRings/\*                                                                   | ""                                                              |
| service_account_file | string | no                                          | Path to the service account file used to authenticate with the Cloud KMS API.                                                                                                                  | Value of `GOOGLE_APPLICATION_CREDENTIALS` environment variable. |

### Authenticating with the Cloud KMS API

The plugin uses the Application Default Credentials to authenticate with the
Google Cloud KMS API, as documented by [Setting Up Authentication For Server to
Server](https://cloud.google.com/docs/authentication/production). When SPIRE
Server is running inside GCP, it will use the default service account
credentials available to the instance it is running under. When running outside
GCP, or if non-default credentials are needed, the path to the service account
file containing the credentials may be specified using the
`GOOGLE_APPLICATION_CREDENTIALS` environment variable or the
`service_account_file` configurable (see [Configuration](#configuration)).

### Use of key versions

In Cloud KMS, the cryptographic key material that is used to sign data is stored
in a key version (CryptoKeyVersion). A key (CryptoKey) can have zero or more key
versions.

For each SPIRE Key ID that the server manages, this plugin maintains a
CryptoKey. When a key is rotated, a new CryptoKeyVersion is added to the
CryptoKey and the rotated CryptoKeyVersion is scheduled for destruction.

### Management of keys

The plugin assigns
[labels](https://cloud.google.com/kms/docs/creating-managing-labels) to the
CryptoKeys that it manages in order to keep track of them. The use of these
labels also allows efficient filtering when performing the listing operations in
the service. All the labels are named with the `spire-` prefix.
Users don't need to interact with the labels managed by the plugin. The
following table is provided for informational purposes only:

| Label             | Description                                                                                                                             |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| spire-server-td   | SHA-1 checksum of the trust domain name of the server.                                                                                  |
| spire-server-id   | An identifier that is unique to the server. This is handled by either the `key_identifier_file` or `key_identifier_value` configurable. |
| spire-last-update | Unix time of the last time that the plugin updated the CryptoKey to keep it active.                                                     |
| spire-active      | Indicates if the CryptoKey is still in use by the plugin.                                                                               |

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

The plugin attempts to detect and prune stale CryptoKeys. To facilitate stale
CryptoKey detection, the plugin actively updates the `spire-last-update` label
on all CryptoKeys managed by the server every 6 hours. The plugin periodically
scans the CryptoKeys looking for active CryptoKeys within the trust domain that
have a `spire-last-update` value older than two weeks and don't belong to the
server. The corresponding CryptoKeyVersions of those stale CryptoKeys are
scheduled for destruction, and the `spire-active` label in the CryptoKey is
updated to indicate that the CryptoKey is no longer active. Additionally, if
the plugin detects that a CryptoKey doesn't have any enabled CryptoKeyVersions,
it also updates the `spire-active` label in the CryptoKey to set it as inactive.

### Required permissions

The plugin requires the following IAM permissions be granted to the
authenticated service account in the configured key ring:

```text
cloudkms.cryptoKeys.create
cloudkms.cryptoKeys.getIamPolicy
cloudkms.cryptoKeys.list
cloudkms.cryptoKeys.setIamPolicy
cloudkms.cryptoKeys.update
cloudkms.cryptoKeyVersions.create
cloudkms.cryptoKeyVersions.destroy
cloudkms.cryptoKeyVersions.get
cloudkms.cryptoKeyVersions.list
cloudkms.cryptoKeyVersions.useToSign
cloudkms.cryptoKeyVersions.viewPublicKey
```

### IAM policy

Google Cloud resources are organized hierarchically, and resources inherit the
allow policies of the parent resource. The plugin sets a default IAM policy to
CryptoKeys that it creates. Alternatively, a user defined IAM policy can be
defined.
The effective allow policy for a CryptoKey is the union of the allow policy set
at that resource by the plugin and the allow policy inherited from its parent.

#### Default IAM policy

The plugin defines a default IAM policy that is set to created CryptoKeys. This
policy binds the authenticated service account with the Cloud KMS CryptoKey
Signer/Verifier (`roles/cloudkms.signerVerifier`) predefined role.

```json
{
    "bindings": [
        {
            "role": "roles/cloudkms.signerVerifier",
            "members": [
                "serviceAccount:SERVICE_ACCOUNT_EMAIL"
            ]
        }
    ],
    "version": 3
}

```

The `roles/cloudkms.signerVerifier` role grants the following permissions:

```text
cloudkms.cryptoKeyVersions.useToSign
cloudkms.cryptoKeyVersions.useToVerify
cloudkms.cryptoKeyVersions.viewPublicKey
cloudkms.locations.get
cloudkms.locations.list
resourcemanager.projects.get
```

#### Custom IAM policy

It is also possible for the user to define a custom IAM policy that will be
attached to the created CryptoKeys. If the configurable `key_policy_file` is
set, the plugin uses the policy defined in the file instead of the default
policy.
Custom IAM policies must be defined using
[version 3](https://cloud.google.com/iam/docs/policies#versions).

## Sample Plugin Configuration

```hcl
KeyManager "gcp_kms" {
    plugin_data {        
        key_ring = "projects/project-id/locations/location/keyRings/keyring"
        key_metadata_file = "./gcpkms-key-metadata"
    }
}
```

## Supported Key Types

The plugin supports all the key types supported by SPIRE: `rsa-2048`,
`rsa-4096`, `ec-p256`, and `ec-p384`.
