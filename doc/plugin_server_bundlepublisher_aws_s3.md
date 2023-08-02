# Server plugin: BundlePublisher "aws_s3"

The `aws_s3` plugin puts the current trust bundle of the server in a designated
Amazon S3 bucket, keeping it updated.

The plugin accepts the following configuration options:

| Configuration     | Description                                                                                                                                                    | Required                                                               | Default                                             |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|-----------------------------------------------------|
| access_key_id     | AWS access key id.                                                                                                                                             | Required only if AWS_ACCESS_KEY_ID environment variable is not set.    | Value of AWS_ACCESS_KEY_ID environment variable.    |
| secret_access_key | AWS secret access key.                                                                                                                                         | Required only if AWS_SECRET_ACCESSKEY environment variable is not set. | Value of AWS_SECRET_ACCESSKEY environment variable. |
| region            | AWS region to store the trust bundle.                                                                                                                          | Yes.                                                                   |                                                     |
| bucket            | The Amazon S3 bucket name to which the trust bundle is uploaded.                                                                                               | Yes.                                                                   |                                                     |
| object_key        | The object key inside the bucket.                                                                                                                              | Yes.                                                                   |                                                     |
| format            | Format in which the trust bundle is stored, &lt;spiffe &vert; jwks &vert; pem&gt;. See [Supported bundle formats](#supported-bundle-formats) for more details. | Yes.                                                                   |                                                     |

## Supported bundle formats

The following bundle formats are supported:

### SPIFFE format

The trust bundle is represented as an RFC 7517 compliant JWK Set, with the specific parameters defined in the [SPIFFE Trust Domain and Bundle specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format). Both the JWT authorities and the X.509 authorities are included.

### JWKS format

The trust bundle is encoded as an RFC 7517 compliant JWK Set, omitting SPIFFE-specific parameters. Both the JWT authorities and the X.509 authorities are included.

### PEM format

The trust bundle is formatted using PEM encoding. Only the X.509 authorities are included.

## AWS IAM Permissions

The user or role identified by the configured credentials must have the `s3:PutObject` IAM permissions.

## Sample configuration

The following configuration uploads the local trust bundle contents to the `example.org` object in the `spire-trust-bundle` bucket. The AWS access key id and secret access key are obtained from the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESSKEY environment variables.

```hcl
    BundlePublisher "aws_s3" {
        plugin_data {
            region = "us-east-1"
            bucket = "spire-trust-bundle"
            object_key = "example.org"
            format = "spiffe"
        }
    }
```
