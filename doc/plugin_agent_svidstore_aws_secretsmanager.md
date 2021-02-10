# Agent plugin: SVIDStore "aws_secretsmanager"

The `aws_secretsmanager` plugin automatically stores X509-SVIDs as a marshalled [workload.X509SVIDResponse](https://github.com/spiffe/go-spiffe/blob/master/v2/proto/spiffe/workload/workload.proto#L10), 
in [AWS Secrets Manager](https://aws.amazon.com/es/secrets-manager/) Secret Binary,

This plugin will create or update Secrets with latests X509-SVID and any rotation is will update secret.
* Secrets will created/updated for all configured regions *

| Configuration      | Description |
| ------------------ | ----------- |
| access_key_id      |  AWS access key id. Default: value of AWS_ACCESS_KEY_ID environment variable. |
| secret_access_key  |  AWS secret access key. Default: value of AWS_SECRET_ACCESS_KEY environment variable. |
| regions            |  AWS regions to store the secrets. |

A sample configuration:

```
    SVIDStore "aws_secretsmanager" {
       plugin_data {
           access_key_id = "ACCESS_KEY_ID"
           secret_access_key = "SECRET_ACCESS_KEY"
           regions = [ "us-east-1", "us-west-2" ]
       }
    }
```

### Store selectors

Selectors are used as a source for information about AWS Secret. And a Secret is created or updated to keep it updated with latests X509-SVID.

| Selector                        | Example                                   | Description                                    |
| ------------------------------- | ----------------------------------------- | ---------------------------------------------- |
| `aws_secretsmanager:secretname` | `aws_secretsmanager:secretname:some-name` | The secrets name where SVID will be stored |
| `aws_secretsmanager:arn`        | `aws_secretsmanager:arn:some-arn`         | The secrets ARN where SVID will be stored |
| `aws_secretsmanager:kmskeyid    | `aws_secretmanager:kmskeyid`              | The custom key managers Key ID used to encrypt secret, in case it is not provided default KMSKeyID from Secrets manager will be used |

