# Server plugin: NodeAttestor "aws_iid"

*Must be used in conjunction with the server-side aws_iid plugin*

The `aws_iid` plugin automatically attests instances using the AWS Instance Metadata API and the AWS Instance Identity document. It also allows an operator to use AWS Instance IDs when defining SPIFFE ID attestation policies. 

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| identity_document_url  |  URL pointing to the [AWS Instance Identity Document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html). | http://169.254.169.254/latest/dynamic/instance-identity/document |
| identity_signature_url | URL pointing to the [AWS Instance Identity Signature](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html). | http://169.254.169.254/latest/dynamic/instance-identity/signature |
