# Server plugin: NodeAttestor "aws_iid"

*Must be used in conjunction with the agent-side aws_iid plugin*

The `aws_iid` plugin automatically attests instances using the AWS Instance
Metadata API and the AWS Instance Identity document. It also allows an operator
to use AWS Instance IDs when defining SPIFFE ID attestation policies. Agents
attested by the aws_iid attestor will be issued a SPIFFE ID like
`spiffe://example.org/agent/aws_iid/ACCOUNT_ID/REGION/INSTANCE_ID`. Additionally,
this plugin resolves the agent's AWS IID-based SPIFFE ID into a set of selectors.

| Configuration       | Description | Default                 |
| --------------------| ----------- | ----------------------- |
| `access_key_id`     | AWS access key id     | Value of `AWS_ACCESS_KEY_ID` environment variable |
| `secret_access_key` | AWS secret access key | Value of `AWS_SECRET_ACCESS_KEY` environment variable |
| `skip_block_device` | Skip anti-tampering mechanism which checks to make sure that the underlying root volume has not been detached prior to attestation. | false |

The user or role identified by the credentials must have permissions for `ec2:DescribeInstances`.

The following is an example for a IAM policy needed to get instance's info from AWS.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ec2:DescribeInstances",
            "Resource": "*"
        }
    ]
}
```

For more information on security credentials, see https://docs.aws.amazon.com/general/latest/gr/aws-security-credentials.html.

A sample configuration:

```
    NodeAttestor "aws_iid" {
        plugin_data {
			access_key_id = "ACCESS_KEY_ID"
			secret_access_key = "SECRET_ACCESS_KEY"
        }
    }
```

This plugin generates the following selectors related to the instance where the agent is running:

| Selector            | Example                                           | Description                                                      |
| ------------------- | ------------------------------------------------- | ---------------------------------------------------------------- |
| Instance Tag        | `tag:name:blog`                                   | The key (e.g. `name`) and value (e.g. `blog`) of an instance tag |
| Security Group ID   | `sg:id:sg-01234567`                               | The id of the security group the instance belongs to             |
| Security Group Name | `sg:name:blog`                                    | The name of the security group the instance belongs to           |
| IAM role            | `iamrole:arn:aws:iam::123456789012:role/Blog`     | An IAM role within the instance profile for the instance         |

 All of the selectors have the type `aws_iid`.

 The `IAM role` selector is included in the generated set of selectors only if the instance has an IAM Instance Profile associated.

