# Server plugin: NodeResolver "azure_msi"

*Must be used in conjunction with the server azure_msi nodeattestor plugin*

The `azure_msi` plugin attests resolves nodes running in Microsoft Azure that
have attested using Managed Service Identity (MSI). The resolver extracts the
Tenant ID and Principal ID from the agent SPIFFE ID and uses the various Azure
services to get information for building a set of selectors.

The set of selectors current supported:

| Selector               | Example                                                | Description                                                |
| ---------------------- | ------------------------------------------------------ | -----------------------------------------------------------|
| Subscription ID        | `subscription-id:d5b40d61-272e-48da-beb9-05f295c42bd6` | The subscription the node belongs to |
| Virtual Machine Name   | `vm-name:frontend:blog`                                | The name of the virtual machine (e.g. `blog`) qualified by the resource group (e.g. `frontend`)
| Network Security Group | `network-security-group:frontend:webservers`           | The name of the network security group (e.g. `webservers`) qualified by the resource group (e.g. `frontend`)
| Virtual Network        | `virtual-network:frontend:vnet`                        | The name of the virtual network (e.g. `vnet`) qualified by the resource group (e.g. `frontend`)
| Virtual Network Subnet | `virtual-network:frontend:vnet:default`                | The name of the virtual network subnet (e.g. `default`) qualfied by the virtual network and resource group

The server plugin does not need to be running in Azure in order to perform node
resolution. The plugin can be configured to authenticate with Azure services
using either MSI or credentials for an application registered in an Azure AD tenant.

| Configuration   | Description | Default                 |
| --------------- | ----------- | ----------------------- |
| `use_msi`       | Whether or not to use MSI to authenticate to Azure services. If true, the `tenants` map must be empty. | |
| `tenants`       | A map of tenants, keyed by tenant ID. `use_msi` must be false if this value is set. | |

Each tenant in the tenant configuration map supports the following:

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| `subscription_id` | The subscription the tenant resides in | |
| `app_id` | The application id | |
| `app_secret` | The application secret | |

A sample configuration:

```
    NodeResolver "azure_msi" {
        enabled = true
        plugin_data {
            use_msi = false
            tenants = {
                subscription_id = SUBSCRIPTION_ID
                app_id = APP_ID
                app_secret = APP_SECRET
            }
        }
    }
```
