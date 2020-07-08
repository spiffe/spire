# Server plugin: NodeResolver "aws_iid"

*Must be used in conjunction with the aws_iid node attestor plugin*

The `aws_iid` resolver plugin resolves AWS IID-based SPIFFE ID's into a set
of selectors.

## Selectors

| Selector            | Example                                           | Description                                                      |
| ------------------- | ------------------------------------------------- | ---------------------------------------------------------------- |
| Instance Tag        | `tag:name:blog`                                   | The key (e.g. `name`) and value (e.g. `blog`) of an instance tag |
| Security Group ID   | `sg:id:sg-01234567`                               | The id of the security group the instance belongs to             |
| Security Group Name | `sg:name:blog`                                    | The name of the security group the instance belongs to           |
| IAM role            | `iamrole:arn:aws:iam::123456789012:role/Blog`     | An IAM role within the instance profile for the instance         |

 All of the selectors have the type `aws_iid`.

## Configuration

| Configuration        | Description                  | Default                                               |
| -------------------- | ---------------------------- | ----------------------------------------------------- |
| `access_key_id`      | AWS access key id            | Value of `AWS_ACCESS_KEY_ID` environment variable     |
| `secret_access_key`  | AWS secret access key        | Value of `AWS_SECRET_ACCESS_KEY` environment variable |

The user or role identified by the credentials must have permissions for
`ec2:DescribeInstances` and `iam:GetInstanceProfile`.

The following is an example for a IAM policy needed to get instance's info from AWS.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "iam:GetInstanceProfile"
            ],
            "Resource": "*"
        }
    ]
}
```

For more information on security credentials, see https://docs.aws.amazon.com/general/latest/gr/aws-security-credentials.html.

A sample configuration:

```
    NodeResolver "aws_iid" {
        enabled = true
        plugin_data {
			access_key_id = "ACCESS_KEY_ID"
			secret_access_key = "SECRET_ACCESS_KEY"
        }
    }
```
