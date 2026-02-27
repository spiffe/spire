# Server plugin: KeyManager "aws_kms"

The `aws_kms` key manager plugin leverages the AWS Key Management Service (KMS) to create, maintain and rotate key pairs (as [Customer Master Keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys), or CMKs), and sign SVIDs as needed, with the private key never leaving KMS.

The plugin supports two modes of operation:

- **Standard Mode**: Each SPIRE server manages its own set of keys identified by a unique server ID
- **Shared Keys Mode**: Multiple SPIRE servers (including multi-region deployments) can discover and use the same signing keys based on configurable templates and regular expressions

## Configuration

The plugin accepts the following configuration options:

| Key                  | Type   | Required                                    | Description                                                                                                                 | Default                                                 |
|----------------------|--------|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| access_key_id        | string | see [AWS KMS Access](#aws-kms-access)       | The Access Key Id used to authenticate to KMS                                                                               | Value of the AWS_ACCESS_KEY_ID environment variable     |
| secret_access_key    | string | see [AWS KMS Access](#aws-kms-access)       | The Secret Access Key used to authenticate to KMS                                                                           | Value of the AWS_SECRET_ACCESS_KEY environment variable |
| region               | string | yes                                         | The region where the keys will be stored                                                                                    |                                                         |
| key_identifier_file  | string | See [Key Identifier](#key-identifier)       | A file path location where information about generated keys will be persisted                                               |                                                         |
| key_identifier_value | string | See [Key Identifier](#key-identifier)       | A static identifier for the SPIRE server instance (used instead of `key_identifier_file`)                                   |                                                         |
| key_policy_file      | string | no                                          | A file path location to a custom key policy in JSON format                                                                  | ""                                                      |
| key_tags             | map    | no                                          | A map of tags to apply to created keys                                                                                      |                                                         |
| shared_keys          | object | no                                          | Configuration for shared keys mode (see [Shared Keys Configuration](#shared-keys-configuration))                            |                                                         |

### Key Identifier

In standard mode, either `key_identifier_file` or `key_identifier_value` is required. In shared keys mode, these are optional as keys are identified using templates and regex patterns instead.

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

### Shared Keys Configuration

The plugin supports a shared keys mode that allows multiple SPIRE servers to discover and use the same signing keys. This is useful for multi-server and multi-region deployments where servers need to coordinate key usage.

When the `shared_keys` configuration block is present, the plugin operates in shared keys mode. This block accepts the following options:

| Key                       | Type   | Required | Description                                                                                                                  |
|---------------------------|--------|----------|------------------------------------------------------------------------------------------------------------------------------|
| jwt_key_alias_template    | string | yes      | A Go template to generate the KMS alias for JWT keys                                                                         |
| lock_alias_template       | string | yes      | A Go template to generate the KMS alias used for distributed locking during rotation                                         |
| key_id_extraction_regex   | string | yes      | A regex with one capturing group to extract the SPIRE Key ID from KMS alias names                                            |

> **Note**: Any existing keys cannot be used after turning on the shared keys feature.

#### Template Context

The alias templates support [Sprig v3](http://masterminds.github.io/sprig/) functions and have access to the following variables:

- `.Region`: The configured AWS region
- `.TrustDomain`: The configured trust domain
- `.ServerID`: The server ID (if configured)
- `.Env`: The value of the `SPIRE_ENV` environment variable
- `.KeyID`: The SPIRE Key ID being requested (e.g., `jwt-signer`, `x509-CA-A`)

#### Regex-based Discovery

The `key_id_extraction_regex` must include **one capturing group** that extracts the SPIRE Key ID from the KMS alias name.

Example: `^alias/spire/[^/]+/([^/]+)$` matches `alias/spire/us-east-1/jwt-signer` and extracts `jwt-signer`.

#### Distributed Locking and Coordination

When multiple servers share keys, they must coordinate to prevent race conditions during key rotation:

1. **Distributed Locking**: Before creating or rotating a key, the plugin acquires a distributed lock by creating a KMS alias determined by `lock_alias_template`
2. **Freshness Check**: If the lock is acquired, the plugin checks if the key was recently rotated (within the last 15 minutes) by another server. If so, it reuses the existing fresh key instead of generating a duplicate

### Key Tagging

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

### Standard Mode (Single Server)

Basic configuration for a single SPIRE server:

```hcl
KeyManager "aws_kms" {
    plugin_data {
        region = "us-east-2"
        key_identifier_file = "./server_id"
    }
}
```

### Standard Mode with Tags

```hcl
KeyManager "aws_kms" {
    plugin_data {
        region = "us-east-2"
        key_identifier_file = "./server_id"
        key_tags = {
            Environment = "production"
            Team        = "security"
            Component   = "spire"
        }
    }
}
```

### Shared Keys Mode (Multi-Server)

Configuration for multiple SPIRE servers sharing keys:

```hcl
KeyManager "aws_kms" {
    plugin_data {
        region = "us-east-1"
        
        shared_keys {
            # Template matches alias/spire/us-east-1/jwt-signer
            jwt_key_alias_template = "alias/spire/{{ .Region }}/{{ .KeyID }}"
            
            # Regex extracts 'jwt-signer' from the alias
            key_id_extraction_regex = "^alias/spire/[^/]+/([^/]+)$"
            
            # Lock alias for safe rotation coordination
            lock_alias_template = "alias/spire/lock/{{ .Region }}/{{ .KeyID }}"
        }
    }
}
```

### Shared Keys Mode with Environment-based Keys

```hcl
KeyManager "aws_kms" {
    plugin_data {
        region = "us-west-2"
        
        shared_keys {
            # Use environment variable for multi-environment deployments
            jwt_key_alias_template = "alias/spire/{{ .Env }}/{{ .Region }}/{{ .KeyID }}"
            key_id_extraction_regex = "^alias/spire/[^/]+/[^/]+/([^/]+)$"
            lock_alias_template = "alias/spire/lock/{{ .Env }}/{{ .Region }}/{{ .KeyID }}"
        }
        
        key_tags = {
            Environment = "production"
            Region      = "us-west-2"
        }
    }
}
```

## Supported Key Types and TTL

The plugin supports all the key types supported by SPIRE: `rsa-2048`, `rsa-4096`, `ec-p256`, and `ec-p384`.
