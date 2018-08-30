# Agent plugin: NodeAttestor "azure_msi"

*Must be used in conjunction with the server-side azure_msi plugin*

The `azure_msi` plugin attests nodes running in Microsoft Azure that have 
Managed Service Identity (MSI) enabled. Agent nodes acquire a signed MSI token
which is passed to the server. The server validates the signed MSI token and
extracts the Tenant ID and Principal ID to form the agent SPIFFE ID. The SPIFFE
ID has the form:

```
spiffe://<trust domain>/spire/agent/azure_msi/<tenant_id>/<principal_id>
```

The agent needs to be running in Azure, in a VM with MSI enabled, in order to
use this method of node attestation.

| Configuration   | Description | Default                 |
| --------------- | ----------- | ----------------------- |
| `resource_id`   | The resource ID (or audience) to request for the MSI token. The server will reject tokens with resource IDs it does not recognize | https://management.azure.com/ |

It is important to note that the resource ID MUST be for a well known Azure
service, or an app ID for a registered app in Azure AD. Azure will not issue an
MSI token for resources it does not know about.

The resource ID that is chosen has security implications. If the server was
compromised, the agent would be granting the compromised server access to
whatever resource on behalf of the agent VM. If that is a concern for your
deployment, you should register an application with Azure AD with a dummy
URI that you can use as a resource instead to limit the scope of replay-ability.

A sample configuration with the default resource ID (i.e. resource manager):

```
    NodeAttestor "azure_msi" {
        plugin_data {
        }
    }
```

A sample configuration with a custom resource ID:

```
    NodeAttestor "azure_msi" {
        plugin_data {
            resource_id = "http://example.org/app/"
        }
    }
```
