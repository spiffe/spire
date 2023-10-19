# Agent plugin: SVIDStore "aws_secretsmanager"

The `aws_secretsmanager` plugin stores in [AWS Secrets Manager](https://aws.amazon.com/es/secrets-manager/) the resulting X509-SVIDs of the entries that the agent is entitled to.

## Secret format

The format that is used to store in a secret the issued identity is the following:

```json
{
    "spiffeId": "spiffe://example.org",
    "x509Svid": "X509_CERT_CHAIN_PEM",
    "x509SvidKey": "PRIVATE_KEY_PEM",
    "bundle": "X509_BUNDLE_PEM",
    "federatedBundles": {
        "spiffe://federated.org": "X509_FEDERATED_BUNDLE_PEM"
    }
}
```

## Required AWS IAM permissions

This plugin requires the following IAM permissions in order to function:

```text
secretsmanager:DescribeSecret
secretsmanager:CreateSecret
secretsmanager:RestoreSecret
secretsmanager:PutSecretValue
secretsmanager:TagResource
secretsmanager:DeleteSecret
kms:Encrypt
```

Please note that this plugin does not read secrets it has stored and therefore does not require read permissions.

## Configuration

When the SVIDs are updated, the plugin takes care of updating them in AWS Secrets Manager.

| Configuration     | Description                                                                         |
|-------------------|-------------------------------------------------------------------------------------|
| access_key_id     | AWS access key id. Default: value of AWS_ACCESS_KEY_ID environment variable.        |
| secret_access_key | AWS secret access key. Default: value of AWS_SECRET_ACCESSKEY environment variable. |
| region            | AWS region to store the secrets.                                                    |

A sample configuration:

```hcl
    SVIDStore "aws_secretsmanager" {
       plugin_data {
           access_key_id = "ACCESS_KEY_ID"
           secret_access_key = "SECRET_ACCESS_KEY"
           region = "us-east-1"
       }
    }
```

## Selectors

The selectors of the type `aws_secretsmanager` are used to describe metadata that is needed by the plugin in order to store secret values in AWS Secrets Manager.

| Selector                        | Example                                   | Description                                                                                                                                                                                                                                                                                                                                        |
|---------------------------------|-------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `aws_secretsmanager:secretname` | `aws_secretsmanager:secretname:some-name` | Friendly name of the secret where the SVID is stored. If not specified `aws_secretsmanager:arn` must be defined                                                                                                                                                                                                                                    |
| `aws_secretsmanager:arn`        | `aws_secretsmanager:arn:some-arn`         | The Amazon Resource Name (ARN) of the secret where the SVID is stored. If not specified, `aws_secretsmanager:secretname` must be defined                                                                                                                                                                                                           |
| `aws_secretsmanager:kmskeyid`   | `aws_secretmanager:kmskeyid`              | Specifies the ARN, Key ID, or alias of the AWS KMS customer master key (CMK) to be used to encrypt the secrets. Any of the supported ways to identify a AWS KMS key ID can be used. If a CMK in a different account needs to be referenced, only the key ARN or the alias ARN can be used. If not specified, the AWS account's default CMK is used |
