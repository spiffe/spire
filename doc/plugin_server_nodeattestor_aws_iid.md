# Server plugin: NodeAttestor "aws_iid"

*Must be used in conjunction with the agent-side aws_iid plugin*

The `aws_iid` plugin automatically attests instances using the AWS Instance Metadata API and the AWS Instance Identity document. It also allows an operator to use AWS Instance IDs when defining SPIFFE ID attestation policies. 
Agents attested by the aws_iid attestor will be issued a SPIFFE ID like `spiffe://example.org/agent/aws_iid/ACCOUNT_ID/INSTANCE_ID`

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| trust_domain  | The trust domain that the agent belongs to. |  |
| access_id     | The AWS access secret key id of IAM user with action policy to allow "ec2:DescribeInstances". An ec2 client to introspect the instance being attested is created. | Value of `AWS_ACCESS_KEY_ID` environment variable |
| secret        | Specifies the AWS access secret key corresponding to the access_id. | Value of `AWS_SECRET_ACCESS_KEY` environment variable |
| skip_block_device | Skip anti-tampering mechanism which checks to make sure that the underlying root volume has not been detached prior to attestation. | false |

