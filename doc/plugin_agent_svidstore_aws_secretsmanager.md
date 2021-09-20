# Agent plugin: SVIDStore "aws_secretsmanager"

The `aws_secretsmanager` plugin automatically stores X509-SVIDs in JSON format, 
in [AWS Secrets Manager](https://aws.amazon.com/es/secrets-manager/) Secret Binary,

example:
```
{
	"spiffeId": "spiffe://example.org",
	"x509Svid": "X509_CERT_CHAIN_PEM",
	"x509SvidKey": "PRIVATE_KET_PEM",
	"bundle": "X509_BUNDLE_PEM",
	"federatedBundles": {
		"spiffe://federated.org": "X509_FEDERATED_BUNDLE_PEM"
	}
}
```

This plugin will create or update Secrets with latests X509-SVID and any rotation is will update secret.

| Configuration      | Description |
| ------------------ | ----------- |
| access_key_id      |  AWS access key id. Default: value of AWS_ACCESS_KEY_ID environment variable. |
| secret_access_key  |  AWS secret access key. Default: value of AWS_SECRET_ACCESSKEY environment variable. |
| region             |  AWS region to store the secrets. |

A sample configuration:

```
    SVIDStore "aws_secretsmanager" {
       plugin_data {
           access_key_id = "ACCESS_KEY_ID"
           secret_access_key = "SECRET_ACCESS_KEY"
           region = "us-east-1"
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
_
