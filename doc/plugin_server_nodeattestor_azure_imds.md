# Server plugin: NodeAttestor "azure_imds"

_Must be used in conjunction with the [agent-side azure_imds plugin](plugin_agent_nodeattestor_azure_imds.md)_

The `azure_imds` plugin is a newer version of the Azure node attestor, designed to attest nodes running in Microsoft Azure using the Azure Instance Metadata Service (IMDS) attested document. This document, signed by Azure, contains information such as the subscription ID and VM ID. Unlike the older `azure_msi` plugin, `azure_imds` does not require the VM to have a managed identity, making it suitable for a wider range of Azure virtual machines.

ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/azure_imds/<tenant_id>/<subscription_id>/<vm_id>
```

The server does not need to be running in Azure in order to perform node
attestation or to resolve selectors.

## Configuration

| Configuration         | Required | Description                                                                                                                 | Default                                                                  |
| --------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `tenants`             | Required | A map of tenants, keyed by tenant domain, that are authorized for attestation. Tokens for unspecified tenants are rejected. |                                                                          |
| `agent_path_template` | Optional | A URL path portion format of Agent's SPIFFE ID. Describe in text/template format.                                           | `"/{{ .PluginName }}/{{ .TenantID }}/{{ .SubscriptionID }}/{{ .VMID }}"` |

Each tenant in the main configuration supports the following

| Configuration               | Required                                       | Description                                                                                           | Default |
| --------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------- |
| `secret_auth`               | [Optional](#secret-authentication-secret_auth) | Authenticate using an AppReg AppID and AppSecret                                                      |         |
| `token_auth`                | [Optional](#token-authentication-token_auth)   | Authenticate using a AppReg AppID and JWT token stored on disk                                        |         |
| `restrict_to_subscriptions` | [Optional](#authenticating-to-azure)           | Restricts attestation to the listed subscription IDs. Leave unset or empty to allow any subscription. |         |
| `allowed_vm_tags`           | [Optional](#authenticating-to-azure)           | A list of allowed VM tags for the tenant to be used for selectors                                     |         |

If `restrict_to_subscriptions` is provided, any attestation attempt from a subscription ID
not present in the list is rejected before selector resolution occurs.

### Secret Authentication (`secret_auth`)

| Field        | Required | Description                 |
| ------------ | -------- | --------------------------- |
| `app_id`     | Required | The application (client) ID |
| `app_secret` | Required | The application secret      |

### Token Authentication (`token_auth`)

| Field        | Required | Description                   |
| ------------ | -------- | ----------------------------- |
| `app_id`     | Required | The application (client) ID   |
| `token_path` | Required | Path on disk to the JWT token |

Note: The `secret_auth` and `token_auth` are mutually exclusive.

### Authenticating to Azure

This plugin requires credentials to authenticate with Azure in order to inquire
about properties of the attesting node and produce selectors.

By default, the plugin will attempt to use the application default credential by
using the [DefaultAzureCredential API](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#section-readme).
The `DefaultAzureCredential API` attempts to authenticate via the following mechanisms in order -
environment variables, Workload Identity, and Managed Identity; stopping when once succeeds.
When using Workload Identity or Managed Identity, the plugin must be able to fetch the credential for the configured
tenant ID, or else the attestation of nodes using this attestor will fail.

Alternatively, the plugin can be configured to authenticate using one of two methods:

- **Secret-based authentication (`secret_auth`)**: Authenticate using an application's `app_id` and `app_secret` registered in the tenant. This method is suitable for scenarios where you can securely provide and manage secrets.
- **Token-based authentication (`token_auth`)**: Authenticate using an application's `app_id` and a pre-generated JWT token stored on disk (`token_path`). This is useful for environments where secret management is delegated or where tokens are provisioned out-of-band (for example, using Kubernetes projected service account tokens).

Choose only one authentication method per tenant; these options are mutually exclusive.

### Sample Configurations

#### Basic Configuration with Default Authentication

This configuration uses the default Azure credential chain (environment variables, Workload Identity, or Managed Identity):

```hcl
NodeAttestor "azure_imds" {
    plugin_data {
        tenants = {
            "onmicrosoft.com" = {
                restrict_to_subscriptions = ["d5b40d61-272e-48da-beb9-05f295c42bd6"]
            }
        }
    }
}
```

#### Configuration with Secret-Based Authentication

This configuration uses an Azure application's client ID and secret for authentication:

```hcl
NodeAttestor "azure_imds" {
    plugin_data {
        tenants = {
            "onmicrosoft.com" = {
                secret_auth = {
                    app_id = "12345678-1234-1234-1234-123456789012"
                    app_secret = "your-application-secret"
                }
                restrict_to_subscriptions = ["d5b40d61-272e-48da-beb9-05f295c42bd6"]
            }
        }
    }
}
```

#### Configuration with Token-Based Authentication

This configuration uses an Azure application's client ID and a JWT token stored on disk:

```hcl
NodeAttestor "azure_imds" {
    plugin_data {
        tenants = {
            "example.onmicrosoft.com" = {
                token_auth = {
                    app_id = "12345678-1234-1234-1234-123456789012"
                    token_path = "/var/lib/spire/azure-token"
                }
                restrict_to_subscriptions = ["d5b40d61-272e-48da-beb9-05f295c42bd6"]
            }
        }
    }
}
```

#### Advanced Configuration with Multiple Tenants

This configuration demonstrates multiple tenants with different authentication methods and VM tag restrictions:

```hcl
NodeAttestor "azure_imds" {
    plugin_data {
        tenants = {
            "production.onmicrosoft.com" = {
                secret_auth = {
                    app_id = "12345678-1234-1234-1234-123456789012"
                    app_secret = "production-secret"
                }
                restrict_to_subscriptions = [
                    "d5b40d61-272e-48da-beb9-05f295c42bd6",
                    "a1b2c3d4-5678-9012-3456-789012345678"
                ]
                allowed_vm_tags = [
                    "environment",
                    "team"
                ]
            }
            "staging.onmicrosoft.com" = {
                token_auth = {
                    app_id = "87654321-4321-4321-4321-210987654321"
                    token_path = "/var/lib/spire/staging-token"
                }
                restrict_to_subscriptions = ["e2f3g4h5-6789-0123-4567-890123456789"]
                allowed_vm_tags = [
                    "environment"
                ]
            }
        }
    }
}
```

#### Configuration with Custom Agent Path Template

This configuration uses a custom template for generating agent SPIFFE IDs:

```hcl
NodeAttestor "azure_imds" {
    plugin_data {
        tenants = {
            "example.onmicrosoft.com" = {
                restrict_to_subscriptions = ["d5b40d61-272e-48da-beb9-05f295c42bd6"]
            }
        }
        agent_path_template = "/{{ .PluginName }}/{{ .TenantID }}/{{ .SubscriptionID }}/{{ .VMID }}/custom"
    }
}
```

## Selectors

The plugin produces the following selectors.

| Selector                       | Example                                                | Description                                                                                                  |
| ------------------------------ | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Subscription ID                | `subscription-id:d5b40d61-272e-48da-beb9-05f295c42bd6` | The subscription the node belongs to                                                                         |
| Virtual Machine Name           | `vm-name:blog`                                         | The name of the virtual machine (e.g. `blog`)                                                                |
| Virtual Machine Scale Set Name | `vmss-name:myvmss`                                     | The name of the virtual machine scale set (e.g. `myvmss`)                                                    |
| Network Security Group         | `network-security-group:frontend:webservers`           | The name of the network security group (e.g. `webservers`) qualified by the resource group (e.g. `frontend`) |
| Resource Group                 | `resource-group:frontend`                              | The name of the resource group (e.g. `frontend`)                                                             |
| Virtual Machine Location       | `vm-location:eastus`                                   | The location of the virtual machine (e.g. `eastus`)                                                          |
| Virtual Network                | `virtual-network:vnet`                                 | The name of the virtual network (e.g. `vnet`)                                                                |
| Virtual Network Subnet         | `virtual-network-subnet:vnet:default`                  | The name of the virtual network subnet (e.g. `default`) qualified by the virtual network and resource group  |
| Virtual Machine Tag            | `vm-tag:environment:production`                        | Tag key and value on the VM, formatted as `vm-tag:<key>:<value>`                                             |

All the selectors have the type `azure_imds`.

## Agent Path Template

The agent path template is a way of customizing the format of generated SPIFFE IDs for agents.
The template formatter is using Golang text/template conventions, it can reference values provided by the plugin or in a [IMDS attested document](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service#attested-data).
Details about the template engine are available in the [template engine documentation](template_engine.md).

Some useful values are:

| Value           | Description                                                    |
| --------------- | -------------------------------------------------------------- |
| .PluginName     | The name of the plugin                                         |
| .TenantID       | Azure tenant identifier                                        |
| .SubscriptionID | Azure subscription identifier                                  |
| .VMID           | A identifier that is unique to a particular virtual machine ID |

## Security Considerations

The Azure IMDS attested document, which this attestor leverages to prove node metadata, is available to any process running on the node by default. As a result, it is possible for non-agent code running on a node to attest to the SPIRE Server, allowing it to obtain any workload identity that the node is authorized to run.

While many operators choose to configure their systems to block access to the IMDS attested document, the SPIRE project cannot guarantee this posture. To mitigate the associated risk, the `azure_imds` node attestor implements Trust On First Use (or TOFU) semantics. For any given node, attestation may occur only once. Subsequent attestation attempts will be rejected.

It is still possible for non-agent code to complete node attestation before SPIRE Agent can, however this condition is easily and quickly detectable as SPIRE Agent will fail to start, and both SPIRE Agent and SPIRE Server will log the occurrence. Such cases should be investigated as possible security incidents.
