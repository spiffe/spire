# Server plugin: BundlePublisher "aws_rolesanywhere_trustanchor"

> [!WARNING]
> This plugin is only supported when an UpstreamAuthority plugin is used.

The `aws_rolesanywhere_trustanchor` plugin puts the current trust bundle of the server
in a trust anchor, keeping it updated.

The plugin accepts the following configuration options:

| Configuration     | Description                                                                                      | Required                                                                  | Default                                              |
|-------------------|--------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|------------------------------------------------------|
| access_key_id     | AWS access key id.                                                                               | Required only if AWS credentials aren't otherwise set in the environment. | Value of AWS_ACCESS_KEY_ID environment variable.     |
| secret_access_key | AWS secret access key.                                                                           | Required only if AWS credentials aren't otherwise set in the environment. | Value of AWS_SECRET_ACCESS_KEY environment variable. |
| region            | AWS region to store the trust bundle.                                                            | Yes.                                                                      |                                                      |
| trust_anchor_id   | The AWS IAM Roles Anywhere trust anchor id of the trust anchor to which to put the trust bundle. | Yes.                                                                      |                                                      |

## AWS IAM Permissions

The user identified by the configured credentials needs to have `rolesanywhere:UpdateTrustAnchor` permissions.

## Sample configuration

The following configuration puts the local trust bundle contents into the `spire-trust-anchor` trust anchor and keeps it updated. The AWS credentials are obtained from the environment.

```hcl
    BundlePublisher "aws_rolesanywhere_trustanchor" {
        plugin_data {
            region = "us-east-1"
            trust_anchor_id = "153d3e58-cab5-4a59-a0a1-3febad2937c4"
        }
    }
```
