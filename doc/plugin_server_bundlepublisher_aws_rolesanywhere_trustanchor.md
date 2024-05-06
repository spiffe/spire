# Server plugin: BundlePublisher "aws_rolesanywhere_trustanchor"

The `aws_rolesanywhere_trustanchor` plugin puts the current trust bundle of the server
in a trust anchor, keeping it updated. If a trust anchor with the specified name doesn't 
already exist, it will be created.

The plugin accepts the following configuration options:

| Configuration     | Description                                                                                                                                                    | Required                                                                  | Default                                              |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|------------------------------------------------------|
| access_key_id     | AWS access key id.                                                                                                                                             | Required only if AWS credentials aren't otherwise set in the environment. | Value of AWS_ACCESS_KEY_ID environment variable.     |
| secret_access_key | AWS secret access key.                                                                                                                                         | Required only if AWS credentials aren't otherwise set in the environment. | Value of AWS_SECRET_ACCESS_KEY environment variable. |
| region            | AWS region to store the trust bundle.                                                                                                                          | Yes.                                                                      |                                                      |
| trust_anchor_name | The AWS IAM Roles Anywhere trust anchor name to which to put the trust bundle.                                                                                 | Yes.                                                                      |                                                      |

## AWS IAM Permissions

The user identified by the configured credentials may need to have the `rolesanywhere:CreateTrustAnchor`, `rolesanywhere:UpdateTrustAnchor`, `rolesanywhere:ListTrustAnchors`, and `iam:CreateServiceLinkedRole` permissions. Note that these permissions aren't always required in order to perform a trust bundle update. Please see the [IAM Roles Anywhere API Reference](https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/Welcome.html) for more details.

## Sample configuration

The following configuration puts the local trust bundle contents into the `spire-trust-anchor` trust anchor and keeps it updated. The AWS credentials are obtained from the environment.

```hcl
    BundlePublisher "aws_rolesanywhere_trustanchor" {
        plugin_data {
            region = "us-east-1"
            trust_anchor_name = "spire-trust-anchor"
        }
    }
```
