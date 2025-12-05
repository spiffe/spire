# Agent plugin: KeyManager "azure_key_vault"

The `azure_key_vault` key manager plugin leverages the Microsoft Azure Key Vault
Service to create, maintain, and rotate key pairs for agent SVIDs. No Microsoft
Azure principal can view or export the raw cryptographic key material represented
by a key. Instead, Key Vault accesses the key material on behalf of SPIRE Agent.

## Configuration

The plugin accepts the following configuration options:

| Key                  | Type    | Required | Description                                                                                                                                                      | Default |
|----------------------|---------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| key_identifier_value | string  | Yes      | A static identifier for the agent instance. Combined with `agent_id_env_var` to create a unique agent ID.                                                       | ""      |
| key_vault_uri        | string  | Yes      | The Key Vault URI where the keys managed by this plugin reside.                                                                                                  | ""      |
| agent_id_env_var     | string  | Yes      | The name of an environment variable that provides additional agent identification (e.g., `NODE_NAME` for Kubernetes). Combined with `key_identifier_value` to create a unique agent ID. | ""      |
| key_ttl              | string  | No       | How long keys remain valid before being considered stale. Format: duration string (e.g., "336h" for 2 weeks). Used for cleanup and refresh scheduling.            | "336h"  |
| subscription_id      | string  | [Optional](#authenticating-to-azure) | The subscription id.                                                                                                                                             | ""      |
| app_id               | string  | [Optional](#authenticating-to-azure) | The application id.                                                                                                                                              | ""      |
| app_secret           | string  | [Optional](#authenticating-to-azure) | The application secret.                                                                                                                                          | ""      |
| tenant_id            | string  | [Optional](#authenticating-to-azure) | The tenant id.                                                                                                                                                   | ""      |

### Authenticating to Azure

By default, the plugin will attempt to use the application default credential by
using the [DefaultAzureCredential API](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#section-readme).
The `DefaultAzureCredential API` attempts to authenticate via the following mechanisms in order -
environment variables, Workload Identity, and Managed Identity; stopping when once succeeds.
When using Workload Identity or Managed Identity, the plugin must be able to fetch the credential for the configured
tenant ID, otherwise the authentication to Key Vault will fail.

Alternatively, the plugin can be configured to use static credentials for an application
registered within the tenant (`subscription_id`, `app_id`, `app_secret`, and `tenant_id`).

### Agent Identification

The plugin needs a way to uniquely identify each agent instance. The agent ID is
constructed by combining `key_identifier_value` with the value from the environment
variable specified by `agent_id_env_var`:

```
agent_id = "{key_identifier_value}-{env_var_value}"
```

For example, if `key_identifier_value = "cluster-1"` and `agent_id_env_var = "NODE_NAME"` 
with `NODE_NAME=node-abc`, the agent ID would be `"cluster-1-node-abc"`.

This ensures that multiple agents can share the same Key Vault while maintaining
unique key names. The agent ID must not exceed 256 characters.

### Key Refresh and Cleanup

The plugin implements a refresh mechanism to keep keys "alive" while agents are running:

- **Key Refresh**: Keys are refreshed immediately at startup, then periodically every `key_ttl / 2` (e.g., if TTL is 336h, refresh every 168h). This updates the key's `Updated` timestamp in Key Vault.
- **Cleanup at Startup**: When an agent starts, it runs a one-time cleanup (non-blocking) to remove orphaned keys from any agent in the trust domain that haven't been updated for `max(key_ttl, 1 month)`.

The minimum TTL safeguard (1 month) prevents a single agent with a very short TTL from deleting all keys in the Key Vault.

### Management of keys

The plugin assigns [tags](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details#key-tags) to the
keys that it manages in order to keep track of them. All the tags are named with the `spire-` prefix.
Users don't need to interact with the tags managed by the plugin. The
following table is provided for informational purposes only:

| Tag                 | Description                                                                                                                             |
|---------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| spire-agent-td      | A string representing the trust domain name of the agent.                                                                              |
| spire-agent-id      | An identifier that is unique to the agent instance, constructed from `key_identifier_value` and the environment variable value.        |

Keys are named using the format: `spire-agent-key-<AGENT-ID>-<SPIRE-KEY-ID>`, where:
- `AGENT-ID` is the unique agent identifier (from `key_identifier_value` + env var)
- `SPIRE-KEY-ID` is the SPIRE key identifier (e.g., `agent-svid-A` or `agent-svid-B`)

### Required permissions

The identity used needs the following permissions on the Key Vault it's configured to use:

**Key Management Operations**

```text
Get
List
Update
Create
Delete
```

**Cryptographic Operations**

```text
Sign
Verify
```

## Supported Key Types

The plugin supports all the key types supported by SPIRE: `rsa-2048`,
`rsa-4096`, `ec-p256`, and `ec-p384`.

## Example Configuration

### Using Default Azure Credentials (Recommended)

```hcl
KeyManager "azure_key_vault" {
    plugin_data = {
        key_identifier_value = "cluster-1"
        key_vault_uri        = "https://my-keyvault.vault.azure.net/"
        agent_id_env_var     = "NODE_NAME"
        key_ttl              = "336h"  # 2 weeks
    }
}
```

### Using Client Secret Credentials

```hcl
KeyManager "azure_key_vault" {
    plugin_data = {
        key_identifier_value = "cluster-1"
        key_vault_uri        = "https://my-keyvault.vault.azure.net/"
        agent_id_env_var     = "NODE_NAME"
        key_ttl              = "336h"
        tenant_id            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        subscription_id      = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        app_id               = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        app_secret           = "your-app-secret"
    }
}
```

### Kubernetes Example

In Kubernetes, you can use `spec.nodeName` as the environment variable:

```hcl
KeyManager "azure_key_vault" {
    plugin_data = {
        key_identifier_value = "production-cluster"
        key_vault_uri        = "https://prod-keyvault.vault.azure.net/"
        agent_id_env_var     = "NODE_NAME"
    }
}
```

With a DaemonSet, you would set the environment variable:

```yaml
env:
  - name: NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
```

