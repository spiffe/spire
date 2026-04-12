# Server plugin: KeyManager "aws_kms"

The `aws_kms` key manager plugin leverages the AWS Key Management Service (KMS) to create, maintain and rotate key pairs (as [Customer Master Keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys), or CMKs), and sign SVIDs as needed, with the private key never leaving KMS.

## Configuration

The plugin accepts the following configuration options:

| Key                  | Type   | Required                                    | Description                                                                                                                 | Default                                                 |
|----------------------|--------|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| access_key_id        | string | see [AWS KMS Access](#aws-kms-access)       | The Access Key Id used to authenticate to KMS                                                                               | Value of the AWS_ACCESS_KEY_ID environment variable     |
| secret_access_key    | string | see [AWS KMS Access](#aws-kms-access)       | The Secret Access Key used to authenticate to KMS                                                                           | Value of the AWS_SECRET_ACCESS_KEY environment variable |
| region               | string | yes                                         | The region where the keys will be stored                                                                                    |                                                         |
| key_identifier_file  | string | Required if key_identifier_value is not set | A file path location where information about generated keys will be persisted                                               |                                                         |
| key_identifier_value | string | Required if key_identifier_file is not set  | A static identifier for the SPIRE server instance (used instead of `key_identifier_file`)                                   |                                                         |
| key_policy_file      | string | no                                          | A file path location to a custom key policy in JSON format                                                                  | ""                                                      |

### Alias and Key Management

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

The plugin assigns [aliases](https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html) to the Customer Master Keys that it manages. The aliases are used to identify and name keys that are managed by the plugin.

Aliases managed by the plugin have the following form: `alias/SPIRE_SERVER/{TRUST_DOMAIN}/{SERVER_ID}/{KEY_ID}`. The `{SERVER_ID}` is the identifier handled by the `key_identifier_file` or `key_identifier_value` setting. This ID allows multiple servers in the same trust domain (e.g. servers in HA deployments) to manage keys with identical `{KEY_ID}`'s without collision. The `{KEY_ID}` in the alias name is encoded to use a [character set accepted by KMS](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html#API_CreateAlias_RequestSyntax).

The plugin attempts to detect and prune stale aliases. To facilitate stale alias detection, the plugin actively updates the `LastUpdatedDate` field on all aliases every 6 hours. The plugin periodically scans aliases. Any alias encountered with a `LastUpdatedDate` older than two weeks is removed, along with its associated key.

The plugin also attempts to detect and prune stale keys. All keys managed by the plugin are assigned a `Description` of the form `SPIRE_SERVER/{TRUST_DOMAIN}`. The plugin periodically scans the keys. Any key with a `Description` matching the proper form, that is both unassociated with any alias and has a `CreationDate` older than 48 hours, is removed.

### Key tagging

The plugin supports tagging of KMS keys with user-defined tags using the `key_tags` configuration option. These tags are specified as key-value pairs and are applied to all KMS keys created by the plugin.

When using key tagging, you must add the `kms:TagResource` permission to the IAM policy. Key creation will fail without this permission.

**Tag constraints**

- Tag keys must be 1-128 characters long
- Tag values can be 0-256 characters long
- Maximum of 50 tags (AWS KMS limit)
- Tag keys and values must use valid characters: letters, numbers, spaces, and the following special characters: `+ - = . _ : / @`
- Tag keys cannot start with `aws:` (reserved by AWS)
- Tag keys cannot start with `spire-` (reserved for future use)

**Tag validation**
The plugin validates all user-defined tags during configuration. If any tag violates AWS KMS tagging constraints, the plugin will fail to configure and report a detailed error message indicating the specific validation failure.

**Tag lifecycle**
When the `key_tags` configuration block is updated, only newly created keys will be tagged with the new configuration. Existing keys will not have their tags updated.

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
- `kms:TagResource` (required when using key tagging)
- `kms:UpdateAlias`
- `kms:DeleteAlias`

### Key policy

The plugin can generate keys using a default key policy, or it can load and use a user defined policy.

#### Default key policy

The default key policy relies on the SPIRE Server's assumed role. Therefore, it is mandatory
for SPIRE server to assume a role in order to use the default policy.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Allow full access to the SPIRE Server role",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::111122223333:role/example-assumed-role-name"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
             "Sid": "Allow KMS console to display the key and policy",
             "Effect": "Allow",
             "Principal": {
                 "AWS": "arn:aws:iam::111122223333:root"
             },
             "Action": [
                 "kms:Describe*",
                 "kms:List*",
                 "kms:Get*"
             ],
             "Resource": "*"
        }
    ]
}
```

- The first statement of the policy gives the current SPIRE server assumed role full access to the CMK.
- The second statement allows the keys and policy to be displayed in the KMS console.

#### Custom key policy

It is also possible for the user to define a custom key policy. If the configurable `key_policy_file`
is set, the plugin uses the policy defined in the file instead of the default policy.

## Sample Plugin Configuration

### Basic configuration

```hcl
KeyManager "aws_kms" {
    plugin_data {
        region = "us-east-2"
        key_metadata_file = "./key_metadata"
    }
}
```

### Configuration with tags

```hcl
KeyManager "aws_kms" {
    plugin_data {
        region = "us-east-2"
        key_metadata_file = "./key_metadata"
        key_tags = {
            Environment = "production"
            Team        = "security"
            Component   = "spire"
        }
    }
}
```

## Supported Key Types and TTL

The plugin supports all the key types supported by SPIRE: `rsa-2048`, `rsa-4096`, `ec-p256`, and `ec-p384`.
