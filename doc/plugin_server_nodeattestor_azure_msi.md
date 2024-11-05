# Server plugin: NodeAttestor "azure_msi"

*Must be used in conjunction with the agent-side azure_msi plugin*

The `azure_msi` plugin attests nodes running in Microsoft Azure that have
Managed Service Identity (MSI) enabled. Agent nodes acquire a signed MSI token
which is passed to the server. The server validates the signed MSI token and
extracts the Tenant ID and Principal ID to form the agent SPIFFE ID. The SPIFFE
ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/azure_msi/<tenant_id>/<principal_id>
```

The server does not need to be running in Azure in order to perform node
attestation or to resolve selectors.

## Configuration

| Configuration         | Required | Description                                                                                                             | Default                                                   |
|-----------------------|----------|-------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| `tenants`             | Required | A map of tenants, keyed by tenant ID, that are authorized for attestation. Tokens for unspecified tenants are rejected. |                                                           |
| `agent_path_template` | Optional | A URL path portion format of Agent's SPIFFE ID. Describe in text/template format.                                       | `"/{{ .PluginName }}/{{ .TenantID }}/{{ .PrincipalID }}"` |

Each tenant in the main configuration supports the following

| Configuration     | Required                             | Description                                                                                               | Default                         |
|-------------------|--------------------------------------|-----------------------------------------------------------------------------------------------------------|---------------------------------|
| `resource_id`     | Optional                             | The resource ID (or audience) for the tenant's MSI token. Tokens for a different resource ID are rejected | <https://management.azure.com/> |
| `subscription_id` | [Optional](#authenticating-to-azure) | The subscription the tenant resides in                                                                    |                                 |
| `app_id`          | [Optional](#authenticating-to-azure) | The application id                                                                                        |                                 |
| `app_secret`      | [Optional](#authenticating-to-azure) | The application secret                                                                                    |                                 |

It is important to note that the resource ID MUST be for a well known Azure
service, or an app ID for a registered app in Azure AD. Azure will not issue an
MSI token for resources it does not know about.

### Authenticating to Azure

This plugin requires credentials to authenticate with Azure in order to inquire
about properties of the attesting node and produce selectors.

By default, the plugin will attempt to use the application default credential by
using the [DefaultAzureCredential API](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#section-readme).
The `DefaultAzureCredential API` attempts to authenticate via the following mechanisms in order -
environment variables, Workload Identity, and Managed Identity; stopping when once succeeds.
When using Workload Identity or Managed Identity, the plugin must be able to fetch the credential for the configured
tenant ID, or else the attestation of nodes using this attestor will fail.

Alternatively, the plugin can be configured to use static credentials for an application
registered within the tenant (`subscription_id`, `app_id`, and `app_secret`).

For backwards compatibility reasons the authentication configuration is *NOT*
required, however, it will be in a future release.

### Sample Configurations

#### Default Resource ID and App Authentication

```hcl
    NodeAttestor "azure_msi" {
        plugin_data {
            tenants = {
                "00000000-1111-2222-3333-444444444444" = {
                    subscription_id = SUBSCRIPTION_ID
                    app_id = APP_ID
                    app_secret = APP_SECRET
                }
            }
        }
    }
}
```

#### Custom Resource ID and MSI Authentication

```hcl
    NodeAttestor "azure_msi" {
        plugin_data {
            tenants = {
                "00000000-1111-2222-3333-444444444444" = {
                    resource_id = "http://example.org/app/"
                }
            }
        }
    }
```

## Selectors

The plugin produces the following selectors.

| Selector               | Example                                                | Description                                                                                                  |
|------------------------|--------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Subscription ID        | `subscription-id:d5b40d61-272e-48da-beb9-05f295c42bd6` | The subscription the node belongs to                                                                         |
| Virtual Machine Name   | `vm-name:frontend:blog`                                | The name of the virtual machine (e.g. `blog`) qualified by the resource group (e.g. `frontend`)              |
| Network Security Group | `network-security-group:frontend:webservers`           | The name of the network security group (e.g. `webservers`) qualified by the resource group (e.g. `frontend`) |
| Virtual Network        | `virtual-network:frontend:vnet`                        | The name of the virtual network (e.g. `vnet`) qualified by the resource group (e.g. `frontend`)              |
| Virtual Network Subnet | `virtual-network-subnet:frontend:vnet:default`         | The name of the virtual network subnet (e.g. `default`) qualified by the virtual network and resource group  |

All the selectors have the type `azure_msi`.

## Agent Path Template

The agent path template is a way of customizing the format of generated SPIFFE IDs for agents.
The template formatter is using Golang text/template conventions, it can reference values provided by the plugin or in a [MSI access token](https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens#payload-claims).

Some useful values are:

| Value                 | Description                                                |
|-----------------------|------------------------------------------------------------|
| .PluginName           | The name of the plugin                                     |
| .TenantID             | Azure tenant identifier                                    |
| .PrincipalID          | A identifier that is unique to a particular application ID |

## Security Considerations

The Azure Managed Service Identity token, which this attestor leverages to prove node identity, is available to any process running on the node by default. As a result, it is possible for non-agent code running on a node to attest to the SPIRE Server, allowing it to obtain any workload identity that the node is authorized to run.

While many operators choose to configure their systems to block access to the Managed Service Identity token, the SPIRE project cannot guarantee this posture. To mitigate the associated risk, the `azure_msi` node attestor implements Trust On First Use (or TOFU) semantics. For any given node, attestation may occur only once. Subsequent attestation attempts will be rejected.

It is still possible for non-agent code to complete node attestation before SPIRE Agent can, however this condition is easily and quickly detectable as SPIRE Agent will fail to start, and both SPIRE Agent and SPIRE Server will log the occurrence. Such cases should be investigated as possible security incidents.
