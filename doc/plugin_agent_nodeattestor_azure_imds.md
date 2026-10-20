# Agent plugin: NodeAttestor "azure_imds"

_Must be used in conjunction with the [server-side azure_imds plugin](plugin_server_nodeattestor_azure_imds.md)_

The `azure_imds` plugin attests nodes running in Microsoft Azure using the Azure Instance Metadata Service (IMDS).
Agent nodes participate in a challenge-response flow with the server: the agent sends an initial payload, receives a challenge
containing a nonce from the server, fetches an IMDS attested document from Azure using that nonce, fetches compute metadata
from Azure IMDS (to locate the VM for selector resolution), and bundles the attested document along with metadata
(tenant domain and optional locator information read from IMDS) to send back to the server as the challenge response.
The server validates the signed attested document and extracts the Subscription ID and VM ID to form the agent SPIFFE ID. The SPIFFE
ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/azure_imds/<tenant_id>/<subscription_id>/<vm_id>
```

The agent needs to be running in Azure, in a VM or VM Scale Set, in order to
use this method of node attestation.

| Configuration   | Required | Description                                                                                                                | Default |
| --------------- | -------- | -------------------------------------------------------------------------------------------------------------------------- | ------- |
| `tenant_domain` | Required | The domain of the tenant to use for the agent SPIFFE ID. The server will reject tenants with domains it does not recognize | N/A     |

### Virtual Machine Scale Sets

Nodes in Azure Virtual Machine Scale Sets can use this attestor. **Flexible** orchestration scale sets require a SPIRE Agent
build that supports Flexible members together with a matching SPIRE Server; older agent and server pairs may fail to resolve
selectors for Flexible scale sets when IMDS reports scale set membership. **Uniform** orchestration scale sets are supported
as before. Agent identity always comes from the signed attested document (subscription ID and VM ID), not from IMDS locator
fields used for selector resolution.

A sample configuration:

```hcl
    NodeAttestor "azure_imds" {
        plugin_data {
            tenant_domain = "example.com"
        }
    }
```
