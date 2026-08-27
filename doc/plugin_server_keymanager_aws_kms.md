# Server plugin: KeyManager "aws_kms"

The `aws_kms` key manager plugin leverages the AWS Key Management Service (KMS) to create, maintain and rotate key pairs (as [Customer Master Keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys), or CMKs), and sign SVIDs as needed, with the private key never leaving KMS.

## Configuration

The plugin accepts the following configuration options:

| Key                              | Type    | Required                                    | Description                                                                                                               | Default                                                 |
|----------------------------------|---------|---------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| access_key_id                    | string  | see [AWS KMS Access](#aws-kms-access)       | The Access Key Id used to authenticate to KMS                                                                             | Value of the AWS_ACCESS_KEY_ID environment variable     |
| secret_access_key                | string  | see [AWS KMS Access](#aws-kms-access)       | The Secret Access Key used to authenticate to KMS                                                                         | Value of the AWS_SECRET_ACCESS_KEY environment variable |
| region                           | string  | yes                                         | The region where the keys will be stored                                                                                  |                                                         |
| key_identifier_file              | string  | Required if key_identifier_value is not set | A file path location where information about generated keys will be persisted                                             |                                                         |
| key_identifier_value             | string  | Required if key_identifier_file is not set  | A static identifier for the SPIRE server instance (used instead of `key_identifier_file`)                                 |                                                         |
| key_policy_file                  | string  | no                                          | A file path location to a custom key policy in JSON format                                                                | ""                                                      |
| enable_tag_based_key_discovery   | boolean | no                                          | Enable tag-based key discovery (recommended). See [Tag-based Key Discovery](#tag-based-key-discovery).                    | false                                                   |
| multi_region                     | boolean | no                                          | Create new keys as [multi-Region keys](#multi-region-keys).                                                               | false                                                   |
| replica_regions                  | list    | no                                          | Regions that each new key is replicated into. Requires `multi_region`. See [Multi-Region Keys](#multi-region-keys).       | []                                                      |

### Server Instance Identification

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

### Tag-based Key Discovery

> **Recommended.** Enable with `enable_tag_based_key_discovery = true`.

When tag-based key discovery is enabled, the plugin uses the [AWS Resource Groups Tagging API](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/overview.html) to efficiently find only the KMS keys managed by this plugin instance. Keys are identified using the following SPIRE-specific tags applied at creation time:

| Tag key             | Description                                                                    |
|---------------------|--------------------------------------------------------------------------------|
| `spire-server-td`   | The trust domain of the SPIRE server                                           |
| `spire-server-id`   | The server instance identifier                                                 |
| `spire-active`      | Set to `true` for actively managed keys                                        |
| `spire-key-id`      | The SPIRE key identifier                                                       |
| `spire-last-update` | Unix timestamp of the last update (set at creation and refreshed periodically) |

The plugin stamps `spire-last-update` when a key is created (and when migrating an existing key) and periodically refreshes it on all active keys. Any key whose `spire-last-update` timestamp is older than two weeks is considered stale, marked inactive (`spire-active=false`), and its associated KMS key is scheduled for deletion.

**Migration from alias-based discovery:** When enabling tag-based discovery on a server that previously used alias-based discovery, the plugin automatically detects existing untagged keys during startup and applies SPIRE tags to them. No manual migration steps are required.

This mode requires the `tag:GetResources` permission (from the Resource Groups Tagging API). See [AWS KMS Access](#aws-kms-access) for the full permission list.

#### Configuration consistency in HA deployments

The `enable_tag_based_key_discovery` setting should be configured consistently across all SPIRE servers in the same trust domain. As with alias-based discovery, each server periodically refreshes a liveness signal on the keys it manages, and any server will reclaim keys in its trust domain whose signal has not been refreshed for two weeks (this is how keys belonging to a permanently-removed server are cleaned up).

The two discovery modes use independent liveness signals: alias-based discovery refreshes the alias `LastUpdatedDate`, while tag-based discovery refreshes the `spire-last-update` tag. A server only refreshes the signal for its currently configured mode. This has an implication for rollbacks:

- Migrating forward (alias-based to tag-based) across the fleet is safe: keys are tagged automatically on startup and refreshed from then on.
- Rolling back from tag-based to alias-based on part of the fleet while other servers remain tag-based is only safe within the two-week window. A rolled-back server keeps its aliases fresh but stops refreshing `spire-last-update`, so after two weeks the still tag-based servers will treat its in-use keys as abandoned and schedule them for deletion. To roll back safely, change the setting across all servers in the trust domain within that window.

### Alias-based Key Discovery

> **Note:** Alias-based key discovery will be deprecated in a future version and removed in a later one. Enable `enable_tag_based_key_discovery` to migrate.

By default, the plugin uses alias-based key discovery. The plugin assigns [aliases](https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html) to the Customer Master Keys that it manages. Aliases have the following form: `alias/SPIRE_SERVER/{TRUST_DOMAIN}/{SERVER_ID}/{KEY_ID}`. The `{KEY_ID}` in the alias name is encoded to use a [character set accepted by KMS](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html#API_CreateAlias_RequestSyntax).

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
- Tag keys cannot start with `spire-` (reserved for SPIRE-managed tags)

**Tag validation**
The plugin validates all user-defined tags during configuration. If any tag violates AWS KMS tagging constraints, the plugin will fail to configure and report a detailed error message indicating the specific validation failure.

**Tag lifecycle**
When the `key_tags` configuration block is updated, only newly created keys will be tagged with the new configuration. Existing keys will not have their tags updated.

### Multi-Region Keys

Setting `multi_region` to `true` causes the plugin to create new keys as AWS
[multi-Region keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html).
Such a key is a multi-Region _primary_ key that is eligible to be replicated
into other regions, where the resulting replica shares its key ID and key
material and can therefore produce interchangeable signatures.

`multi_region` on its own only makes keys eligible; AWS never replicates a key
by itself. Listing regions in `replica_regions` additionally makes the plugin
replicate each new key into those regions and create the alias — and, under
tag-based discovery, the tags — that a SPIRE server running there needs in
order to find it. Aliases and tags are _independent_ properties of multi-Region
keys, so AWS does not copy them and the plugin must create them per region.

Replication happens asynchronously on a retrying queue per replica region. Key
generation is on the CA rotation path, so it never blocks on a replica region: a
region that is temporarily unreachable is retried with a backoff while the SPIRE
server continues to operate normally, and because each region has its own queue,
one unreachable region does not delay replication into the others. When a key is rotated, the
replica it displaced is deleted only after the alias in that region has been
repointed, so the alias never targets a key that is pending deletion.

#### Limitations

This supports promote-then-start disaster recovery with a **cold standby**. It
is not active-active, and the following constraints apply.

- **Do not run a SPIRE server in a replica region while the primary is
  running.** A failover server must reuse the primary's `key_identifier_value`
  in order to find the replicated aliases, which means both servers would
  discover the same keys and resolve to the same CA journal record, and would
  then rotate against each other. Note that this conflicts with the guidance
  under [Server Instance Identification](#server-instance-identification) that
  the identifier is unique per server; a primary and its standby are the
  exception, and only one of them may run at a time.
- **The datastore in the failover region must be writable before the server
  starts.** SPIRE server startup writes, so a read-only replica database cannot
  host a running server.
- **Replication is not a precondition for use of a key.** The plugin has no way
  to tell the SPIRE server that a key has not yet reached a replica region, so
  a CA may be prepared and activated while replication is still outstanding or
  failing. Sustained replication failures are logged but do not otherwise
  surface.
- **A key's multi-Region property cannot be changed after creation.** Enabling
  `multi_region` affects only keys created from that point on, and keys created
  earlier are never replicated. The server replaces them as it rotates, so a
  deployment converges within roughly a day, during which the replica regions
  have partial coverage.
- **Key policies are not replicated.** `ReplicateKey` attaches the AWS default
  key policy unless one is supplied, so the policy this plugin applies — whether
  from `key_policy_file` or the generated default described under
  [Key policy](#key-policy) — does not carry over to a replica.
- **Cost and quota scale with the number of regions**, since each rotation
  creates a key in the primary region and one in every replica region.

### AWS KMS Access

Access to AWS KMS can be given by either setting the `access_key_id` and `secret_access_key`, or by ensuring that the plugin runs on an EC2 instance with a given IAM role that has a specific set of permissions.

The IAM role must have an attached policy with the following permissions:

- `kms:CreateAlias`
- `kms:CreateKey`
- `kms:DescribeKey`
- `kms:GetPublicKey`
- `kms:ListAliases`
- `kms:ScheduleKeyDeletion`
- `kms:Sign`
- `kms:UpdateAlias`
- `kms:DeleteAlias`

The following additional permissions are required depending on the configuration:

| Permission                    | Required when                                                               |
|-------------------------------|-----------------------------------------------------------------------------|
| `kms:ListKeys`                | Using alias-based key discovery (current default)                           |
| `kms:TagResource`             | Using tag-based key discovery or `key_tags`                                 |
| `tag:GetResources`            | Using tag-based key discovery (`enable_tag_based_key_discovery = true`)     |
| `iam:CreateServiceLinkedRole` | Creating multi-Region keys (`multi_region = true`)                          |
| `kms:ReplicateKey`            | Replicating keys (`replica_regions`); on the primary key, in its key policy |

`tag:GetResources` belongs to the Resource Groups Tagging API, not to KMS. It is an identity-based permission and must be granted in the IAM identity's policy. It cannot be granted through the KMS key policy (including the default policy generated by the plugin).

When `replica_regions` is configured, the identity also needs permissions in each replica region, because the plugin creates and maintains resources there directly: `kms:CreateKey` (which `ReplicateKey` requires in the destination region), `kms:CreateAlias`, `kms:UpdateAlias`, `kms:DescribeKey`, and `kms:ScheduleKeyDeletion` to remove replicas displaced by rotation. Add `kms:TagResource` there as well when tag-based discovery or `key_tags` is in use.

`iam:CreateServiceLinkedRole` is likewise an identity-based permission and cannot be granted through a key policy. AWS KMS requires it from any principal creating a multi-Region primary key, so that it can create the `AWSServiceRoleForKeyManagementServiceMultiRegionKeys` role used to synchronize shared properties between related keys. Without it, `CreateKey` fails when `multi_region` is enabled.

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
        key_identifier_file = "./key_metadata"
    }
}
```

### Configuration with tag-based key discovery (recommended)

```hcl
KeyManager "aws_kms" {
    plugin_data {
        region = "us-east-2"
        key_identifier_file = "./key_metadata"
        enable_tag_based_key_discovery = true
    }
}
```

### Configuration with tags

```hcl
KeyManager "aws_kms" {
    plugin_data {
        region = "us-east-2"
        key_identifier_file = "./key_metadata"
        enable_tag_based_key_discovery = true
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
