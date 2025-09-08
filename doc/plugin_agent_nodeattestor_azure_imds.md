# Agent plugin: NodeAttestor "azure_imds"

_Must be used in conjunction with the server-side azure_imds plugin_

The `azure_imds` plugin attests nodes running in Microsoft Azure using the IMDS metadata.
Agent nodes aqcuire a IMDS attested document from azure and bundles that along with some helpful metadata to send to the server.
The server validates the signed Attested Document and extracts the Subscription ID and VM ID to form the agent SPIFFE ID. The SPIFFE
ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/azure_imds/<tenant_id>/<subscription_id>/<vm_id>
```

The agent needs to be running in Azure, in a VM or VM Scale Set, in order to
use this method of node attestation.

| Configuration   | Required | Description                                                                                                                | Default |
| --------------- | -------- | -------------------------------------------------------------------------------------------------------------------------- | ------- |
| `tenant_domain` | Yes      | The domain of the tenant to use for the agent SPIFFE ID. The server will reject tenants with domains it does not recognize | N/A     |

A sample configuration:

```hcl
    NodeAttestor "azure_imds" {
        plugin_data {
            tenant_domain = "example.com"
        }
    }
```
