# Server plugin: UpstreamCA "aws_pca"

The `aws_pca` plugin uses a certificate authority from AWS Certificate Manager (ACM)
Private Certificate Authority (PCA) to sign intermediate signing certificates for SPIRE Server.

The plugin accepts the following configuration options:

| Configuration             | Description                                                       |
| ------------------------- | ----------------------------------------------------------------- |
| region                    | AWS Region to use                                                 |
| certificate_authority_arn | ARN of the "upstream" CA certificate                              |
| ca_signing_template_arn   | (Optional) ARN of the signing template to use for the server's CA. Defaults to a signing template for end-entity certificates only. See [Using Templates](https://docs.aws.amazon.com/acm-pca/latest/userguide/UsingTemplates.html) for possible values. |
| signing_algorithm         | (Optional) Signing algorithm to use for the server's CA. Defaults to the CA's default. See [Issue Certificate](https://docs.aws.amazon.com/cli/latest/reference/acm-pca/issue-certificate.html) for possible values. |
| assume_role_arn           | (Optional) ARN of an IAM role to assume                           |

The plugin will attempt to load AWS credentials using the default provider chain. This includes credentials from environment variables, shared credentials files, and EC2 instance roles. See [Specifying Credentials](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials) for the full default credentials chain.

See [AWS Certificate Manager Private Certificate Authority](https://aws.amazon.com/certificate-manager/private-certificate-authority/) for more details on ACM Private Certificate Authority.

> Note: A Private Certificate Authority from ACM cannot have it's private key rotated and maintain the same ARN. As a result, restarting SPIRE server is currently required to change which CA from ACM is signing the intermediate CA for SPIRE. It's recommended to use a persisting key store for SPIRE so that existing intermediate signing certificates are maintained upon restart.

Sample configuration:

```
UpstreamCA "aws_pca" {
    plugin_data {
        region = "us-west-2"
        certificate_authority_arn = "arn:aws:acm-pca:us-west-2:123456789012:certificate-authority/12ac02bc-d425-49f7-ab78-570a44972772"
        ca_signing_template_arn = "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
        signing_algorithm = "SHA256WITHECDSA"
        assume_role_arn = "arn:aws:iam::123456789012:role/my-role"
    }
}
```

SPIRE server requires the following policy for the IAM identity used.

> Note: The example provided allows access to all CAs and certificates. Resources should be specified down to limit authorized scope further. See [Configure Access to ACM Private CA](https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaAuthAccess.html).

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ACMPCASigning",
            "Effect": "Allow",
            "Action": [
                "acm-pca:DescribeCertificateAuthority",
                "acm-pca:IssueCertificate",
                "acm-pca:GetCertificate"
            ],
            "Resource": "*"
        }
    ]
}
```
