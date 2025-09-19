# Server plugin: NodeAttestor "aws_iid"

*Must be used in conjunction with the [agent-side aws_iid plugin](plugin_agent_nodeattestor_aws_iid.md)*

The `aws_iid` plugin automatically attests instances using the AWS Instance
Metadata API and the AWS Instance Identity document. It also allows an operator
to use AWS Instance IDs when defining SPIFFE ID attestation policies. Agents
attested by the aws_iid attestor will be issued a SPIFFE ID like
`spiffe://example.org/spire/agent/aws_iid/ACCOUNT_ID/REGION/INSTANCE_ID`. Additionally,
this plugin resolves the agent's AWS IID-based SPIFFE ID into a set of selectors.

## Configuration

| Configuration                        | Description                                                                                                                                                   | Default                                               |
|--------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------|
| `access_key_id`                      | AWS access key id                                                                                                                                             | Value of `AWS_ACCESS_KEY_ID` environment variable     |
| `secret_access_key`                  | AWS secret access key                                                                                                                                         | Value of `AWS_SECRET_ACCESS_KEY` environment variable |
| `skip_block_device`                  | Skip anti-tampering mechanism which checks to make sure that the underlying root volume has not been detached prior to attestation.                           | false                                                 |
| `disable_instance_profile_selectors` | Disables retrieving the attesting instance profile information that is used in the selectors. Useful in cases where the server cannot reach iam.amazonaws.com | false                                                 |
| `assume_role`                        | The role to assume                                                                                                                                            | Empty string, Optional parameter.                     |
| `partition`                          | The AWS partition SPIRE server is running in &lt;aws&vert;aws-cn&vert;aws-us-gov&gt;                                                                          | aws                                                   |
| `verify_organization`                | Verify that nodes belong to a specified AWS Organization [see below](#enabling-aws-node-attestation-organization-validation)                                  |                                                       |
| `validate_eks_cluster_membership`    | Verify that nodes belong to specified EKS clusters [see below](#enabling-aws-node-attestation-eks-cluster-validation)                                         |                                                       |

Sample configuration:

```hcl
    NodeAttestor "aws_iid" {
        plugin_data {
            access_key_id = "ACCESS_KEY_ID"
            secret_access_key = "SECRET_ACCESS_KEY"
        }
    }
```

If `assume_role` is set, the SPIRE server will assume the role as specified by the template `arn:{{Partition}}:iam::{{AccountID}}:role/{{AssumeRole}}` where `Partition` comes from the AWS NodeAttestor plugin configuration if specified otherwise set to 'aws', `AccountID` is taken from the AWS IID document sent by the SPIRE agent to the SPIRE server and `AssumeRole` comes from the AWS NodeAttestor plugin configuration. Details about the template engine are available [here](template_engine.md).

In the following configuration,

```hcl
    NodeAttestor "aws_iid" {
        plugin_data {
            assume_role = "spire-server-delegate"
        }
    }
```

assuming AWS IID document sent from the spire agent contains `accountId : 12345678`, the spire server will assume "arn:aws:iam::12345678:role/spire-server-delegate" role before making any AWS call for the node attestation. If `assume_role` is configured, the spire server will always assume the role even if the both the spire-server and the spire agent is deployed in the same account.

## Enabling AWS Node Attestation Organization Validation

For configuring AWS Node attestation method with organization validation following configuration can be used:

| Field Name                 | Description                                                                                   | Constraints                                |
|----------------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------|
| management_account_id      | Account id of the organzation                                                                 | required                                   |
| management_account_region  | Region of management account id                                                               | optional                                   |
| assume_org_role            | IAM Role name, with capablities to list accounts                                              | required                                   |
| org_account_map_ttl        | Cache the list of accounts for particular time. Should be  >= 1 minute. Defaults to 3 minute. | optional                                   |

Using the block `verify_organization` the org validation node attestation method will be enabled. With above configuration spire server will form and try to assume the role as: `arn:aws:iam::management_account_id:role/assume_org_role`. When not used, block ex. `verify_organization = {}` should not be empty, it should be completely removed as its optional or should have all required parameters namely `management_account_id`, `assume_org_role`.

The role under: `assume_role` must be created in the management account: `management_account_id`, and it should have a trust relationship with the role assumed by spire server. Below is a sample policy depicting the permissions required along with the trust relationship that needs to be created in management account.

Policy :

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "organizations:ListAccounts",
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "SpireOrganizationListAccountRole"
        }
    ]
}
```

Trust Relationship

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CrossAccountAssumeRolePolicy",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::account-id-where-spire-is-running:role/spire-control-plane-root-server",
                    "arn:aws:iam::account-id-where-spire-is-running:role/spire-control-plane-regional-server"
                ]
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

## Enabling AWS Node Attestation EKS Cluster Validation

For configuring AWS Node attestation method with EKS cluster validation following configuration can be used:

| Field Name          | Description                                                                                   | Constraints                                |
|---------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------|
| eks_cluster_names   | List of EKS cluster names that nodes are allowed to belong to                                | required                                   |

Using the block `validate_eks_cluster_membership` the EKS cluster validation node attestation method will be enabled. With above configuration SPIRE server will verify that the attesting node is part of one of the specified EKS clusters. When not used, block ex. `validate_eks_cluster_membership = {}` should not be empty, it should be completely removed as its optional or should have all required parameters namely `eks_cluster_names`.

Sample configuration:

```hcl
NodeAttestor "aws_iid" {
    plugin_data {
        validate_eks_cluster_membership = {
            eks_cluster_names = ["production-cluster", "staging-cluster"]
        }
    }
}
```

The SPIRE server will validate that the attesting EC2 instance is part of an Auto Scaling Group that belongs to one of the specified EKS clusters. The validation process:

1. Retrieves the list of node groups for each specified EKS cluster
2. For each node group, gets the associated Auto Scaling Groups
3. Checks if the attesting instance ID is present in any of these Auto Scaling Groups

### AWS IAM Permissions for EKS Validation

The user or role identified by the configured credentials must have additional permissions for EKS cluster validation:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EKSClusterValidation",
            "Effect": "Allow",
            "Action": [
                "eks:ListNodegroups",
                "eks:DescribeNodegroup",
                "autoscaling:DescribeAutoScalingGroups"
            ],
            "Resource": "*"
        }
    ]
}
```

## Disabling Instance Profile Selectors

In cases where spire-server is running in a location with no public internet access available, setting `disable_instance_profile_selectors = true` will prevent the server from making requests to `iam.amazonaws.com`. This is needed as spire-server will fail to attest nodes as it cannot retrieve the metadata information.

When this is enabled, `IAM Role` selector information will no longer be available for use.

## AWS IAM Permissions

The user or role identified by the configured credentials must have permissions for `ec2:DescribeInstances`.

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

**Note:** Additional permissions are required when using optional validation features:

- For organization validation (`verify_organization`): `organizations:ListAccounts`
- For EKS cluster validation (`validate_eks_cluster_membership`): `eks:ListNodegroups`, `eks:DescribeNodegroup`, `autoscaling:DescribeAutoScalingGroups`

For more information on security credentials, see <https://docs.aws.amazon.com/general/latest/gr/aws-security-credentials.html>.

## Supported Selectors

This plugin generates the following selectors related to the instance where the agent is running:

| Selector            | Example                                               | Description                                                      |
|---------------------|-------------------------------------------------------|------------------------------------------------------------------|
| Availability Zone   | `aws_iid:az:us-west-2b`                               | The Availability Zone in which the instance is running.          |
| IAM role            | `aws_iid:iamrole:arn:aws:iam::123456789012:role/Blog` | An IAM role within the instance profile for the instance         |
| Image ID            | `aws_iid:image:id:ami-5fb8c835`                       | The ID of the AMI used to launch the instance.                   |
| Instance ID         | `aws_iid:instance:id:i-0b22a22eec53b9321`             | The ID of the instance.                                          |
| Instance Tag        | `aws_iid:tag:name:blog`                               | The key (e.g. `name`) and value (e.g. `blog`) of an instance tag |
| Region              | `aws_iid:region:us-west-2`                            | The Region in which the instance is running.                     |
| Security Group ID   | `aws_iid:sg:id:sg-01234567`                           | The id of the security group the instance belongs to             |
| Security Group Name | `aws_iid:sg:name:blog`                                | The name of the security group the instance belongs to           |

All the selectors have the type `aws_iid`.

The `IAM role` selector is included in the generated set of selectors only if the instance has an IAM Instance Profile associated and `disable_instance_profile_selectors = false`

## Security Considerations

The AWS Instance Identity Document, which this attestor leverages to prove node identity, is available to any process running on the node by default. As a result, it is possible for non-agent code running on a node to attest to the SPIRE Server, allowing it to obtain any workload identity that the node is authorized to run.

While many operators choose to configure their systems to block access to the Instance Identity Document, the SPIRE project cannot guarantee this posture. To mitigate the associated risk, the `aws_iid` node attestor implements Trust On First Use (or TOFU) semantics. For any given node, attestation may occur only once. Subsequent attestation attempts will be rejected.

It is still possible for non-agent code to complete node attestation before SPIRE Agent can, however this condition is easily and quickly detectable as SPIRE Agent will fail to start, and both SPIRE Agent and SPIRE Server will log the occurrence. Such cases should be investigated as possible security incidents.
