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
