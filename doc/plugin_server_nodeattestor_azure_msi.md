# Server plugin: NodeAttestor "azure_msi"

*Must be used in conjunction with the agent-side azure_msi plugin*

The `azure_msi` plugin attests nodes running in Microsoft Azure that have
Managed Service Identity (MSI) enabled. Agent nodes acquire a signed MSI token
which is passed to the server. The server validates the signed MSI token and
extracts the Tenant ID and Principal ID to form the agent SPIFFE ID. The SPIFFE
ID has the form:

```
spiffe://<trust domain>/spire/agent/azure_msi/<tenant_id>/<principal_id>
```

The server does not need to be running in Azure in order to perform node
attestation.

## Configuration

| Configuration   | Description | Default                 |
| --------------- | ----------- | ----------------------- |
| `tenants`       | A map of tenants, keyed by tenant ID, that are authorized for attestation. Tokens for unspecified tenants are rejected. | |

Each tenant in the main configuration supports the following

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| `resource_id` | The resource ID (or audience) for the tenant's MSI token. Tokens for a different resource ID are rejected | https://management.azure.com/ |

It is important to note that the resource ID MUST be for a well known Azure
service, or an app ID for a registered app in Azure AD. Azure will not issue an
MSI token for resources it does not know about.

A sample configuration:

```
    NodeAttestor "azure_msi" {
        enabled = true
        plugin_data {
            tenants = {
                // Tenant configured with the default resource id (i.e. the resource manager)
                "9E85E111-1103-48FC-A933-9533FE47DE05" = {}
                // Tenant configured with a custom resource id
                "DD14E835-679A-4703-B4DE-8F00A20C732E" = {
                    resource_id = "http://example.org/app/"
                }
            }
        }
    }
```

## Security Considerations
The Azure Managed Service Identity token, which this attestor leverages to prove node identity, is available to any process running on the node by default. As a result, it is possible for non-agent code running on a node to attest to the SPIRE Server, allowing it to obtain any workload identity that the node is authorized to run.

While many operators choose to configure their systems to block access to the Managed Service Identity token, the SPIRE project cannot guarantee this posture. To mitigate the associated risk, the `azure_msi` node attestor implements Trust On First Use (or TOFU) semantics. For any given node, attestation may occur only once. Subsequent attestation attempts will be rejected.

It is still possible for non-agent code to complete node attestation before SPIRE Agent can, however this condition is easily and quickly detectable as SPIRE Agent will fail to start, and both SPIRE Agent and SPIRE Server will log the occurrence. Such cases should be investigated as possible security incidents.
