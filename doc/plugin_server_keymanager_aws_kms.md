# Server plugin: KeyManager "aws_kms"

The `aws_kms` key manager plugin leverages the AWS Key Management Service (KMS) to create, maintain and rotate key pairs (as [Customer Master Keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys), or CMKs), and sign SVIDs as needed, with the private key never leaving KMS.

## Configuration

The plugin accepts the following configuration options:

| Key                 | Type   | Required                              | Description                                             | Default                                              |
| ------------------- | ------ | ------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------- |
| access_key_id       | string | see [AWS KMS Access](#aws-kms-access) | The Access Key Id used to authenticate to KMS           | Value of the AWS_ACCESS_KEY_ID environment variable      |
| secret_access_key   | string | see [AWS KMS Access](#aws-kms-access) | The Secret Access Key used to authenticate to KMS       | Value of the AWS_SECRET_ACCESS_KEY environment variable  |
| region              | string | yes                                   | The region where the keys will be stored                |                                                      |
| key_metadata_file   | string | yes                                   | A file path location where information about generated keys will be persisted |                                |

### Alias and Key Management

The plugin assigns [aliases](https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html) to the Customer Master Keys that manages. The aliases are used to identify and name keys that are managed by the plugin.

Aliases managed by the plugin have the following form: `alias/SPIRE_SERVER/{TRUST_DOMAIN}/{SERVER_ID}/{KEY_ID}`. The `{SERVER_ID}` is an auto-generated ID unique to the server and is persisted in the _Key Metadata File_ (see the `key_metadata_file` configurable). This ID allows multiple servers in the same trust domain (e.g. servers in HA deployments) to manage keys with identical `{KEY_ID}`'s without collision.

If the _Key Metadata File_ is not found on server startup, the file is recreated, with a new auto-generated server ID. Consequently, if the file is lost, the plugin will not be able to identify keys that it has previously managed and will recreate new keys on demand.

The plugin attempts to detect and prune stale aliases. To facilitate stale alias detection, the plugin actively updates the `LastUpdatedDate` field on all aliases every 6 hours. The plugin periodically scans aliases. Any alias encountered with a `LastUpdatedDate` older than two weeks is removed, along with its associated key.

The plugin also attempts to detect and prune stale keys. All keys managed by the plugin are assigned a `Description` of the form `SPIRE_SERVER/{TRUST_DOMAIN}`. The plugin periodically scans the keys. Any key with a `Description` matching the proper form, that is both unassociated with any alias and has a `CreationDate` older than 48 hours, is removed.

### AWS KMS Access

Access to AWS KMS can be given by either setting the `access_key_id` and `secret_access_key`, or by ensuring that the plugin runs on an EC2 instance with a given IAM role that has a specific set of permissions.

The IAM role must have an attached policy with the following permissions:

- `kms:CreateAlias`
- `kms:CreateKey`
- `kms:DescribeKey`
- `kms:GetPublicKey`
- `kms:ListKeys`
- `kms:ListAliases`
- `kms:ScheduleKeyDeletion`
- `kms:Sign`
- `kms:UpdateAlias`
- `kms:DeleteAlias`

## Sample Plugin Configuration

```
KeyManager "aws_kms" {
    plugin_data {        
        region = "us-east-2"
        key_metadata_file = "./key_metadata"
    }
}
```

## Supported Key Types and TTL

The plugin supports all the key types supported by SPIRE: `rsa-2048`, `rsa-4096`, `ec-p256`, and `ec-p384`.
