# Agent plugin: NodeAttestor "aws_iid"

*Must be used in conjunction with the server-side aws_iid plugin*

The `aws_iid` plugin automatically attests instances using the AWS Instance 
Metadata API and the AWS Instance Identity document. It also allows an operator
to use AWS Instance IDs when defining SPIFFE ID attestation policies.

Generally no plugin data is needed in AWS, and this configuration should be used:

```
    NodeAttestor "aws_iid" {
        plugin_data {}
    }
```

| Configuration          | Description                                        |
| ---------------------- | -------------------------------------------------- |
| ec2_metadata_endpoint  | Endpoint for AWS SDK to retrieve instance metadata |


For testing or non-standard AWS environments, you may need to specify the
Metadata endpoint.  For more information, see [the AWS SDK documentation](https://docs.aws.amazon.com/sdk-for-go/api/aws/ec2metadata/)

```
    NodeAttestor "aws_iid" {
        plugin_data {
            ec2_metadata_endpoint = "http://169.264.169.254/latest"
        }
    }
```
