#  Upstream Authority "vault" Plugin

The vault plugin signs intermediate CA certificates for SPIRE using the Vault PKI Engine.
The plugin does not support the `PublishJWTKey` RPC and is therefore not appropriate for use in nested SPIRE topologies where JWT-SVIDs are in use.

## Configuration

The plugin accepts the following configuration options:

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| vault_addr  | string |   | The URL of the Vault server. (e.g., https://vault.example.com:8443/) | `${VAULT_ADDR}` |
| pki_mount_point  | string |  | Name of the mount point where PKI secret engine is mounted | pki |
| ca_cert_path     | string |  | Path to a CA certificate file used to verify the Vault server certificate. Only PEM format is supported. | `${VAULT_CACERT}` |
| insecure_skip_verify  | string |  | If true, vault client accepts any server certificates | false |
| cert_auth        | struct |  | Configuration for the Client Certificate authentication method | |
| token_auth       | struct |  | Configuration for the Token authentication method | |
| approle_auth     | struct |  | Configuration for the AppRole authentication method | |

The plugin supports **Client Certificate**, **Token** and **AppRole** authentication methods.

- **Client Certificate** method authenticates to Vault using a TLS client certificate. 
- **Token** method authenticates to Vault using the token in a HTTP Request header. 
- **AppRole** method authenticates to Vault using a RoleID and SecretID that are issued from Vault.

The configured token needs to be attached to a policy that has at least the following capabilities:

```hcl
path "pki/root/sign-intermediate" {
  capabilities = ["update"]
}
```

## Client Certificate Authentication

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| cert_auth_mount_point | string |  | Name of the mount point where TLS certificate auth method is mounted | cert |
| client_cert_path | string | | Path to a client certificate file. Only PEM format is supported. | `${VAULT_CLIENT_CERT}` |
| client_key_path  | string | | Path to a client private key file. Only PEM format is supported. | `${VAULT_CLIENT_KEY}` |

```hcl
    UpstreamAuthority "vault" {
        plugin_data {
            vault_addr = "https://vault.example.org/"
            pki_mount_point = "test-pki"
            ca_cert_path = "/path/to/ca-cert.pem"
            cert_auth {
                cert_auth_mount_point = "test-tls-cert-auth"
                client_cert_path = "/path/to/client-cert.pem"
                client_key_path  = "/path/to/client-key.pem"
            }
            // If specify the key-pair as an environment variable and use the modified mount point
            // cert_auth {
            //    cert_auth_mount_point = "test-tls-cert-auth"    
            // }

            // If specify the key-pair as an environment variable and use the default mount point, set the empty structure.
            // cert_auth {}
        }
    }
```
## Token Authentication

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| token | string | | Token string to set into "X-Vault-Token" header | `${VAULT_TOKEN}` |


```hcl
    UpstreamAuthority "vault" {
        plugin_data {
            vault_addr = "https://vault.example.org/"
            pki_mount_point = "test-pki"
            ca_cert_path = "/path/to/ca-cert.pem"
            token_auth {
               token = "<token>" 
            }
            // If specify the token as an environment variable, set the empty structure.
            // token_auth {}
        }
    }
```
## AppRole Authentication

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| approle_auth_mount_point | string | | Name of the mount point where the AppRole auth method is mounted | approle |
| approle_id |string | | An identifier of AppRole | `${VAULT_APPROLE_ID}` |
| approle_secret_id | string | | A credential of AppRole | `${VAULT_APPROLE_SECRET_ID}` |

```hcl
    UpstreamAuthority "vault" {
        plugin_data {
            vault_addr = "https://vault.example.org/"
            pki_mount_point = "test-pki"
            ca_cert_path = "/path/to/ca-cert.pem"
            approle_auth {
               approle_auth_mount_point = "my-approle-auth"
               approle_id = "<Role ID>" // or specified by environment variables
               approle_secret_id = "<Secret ID>" // or specified by environment variables
            }
            // If specify the approle_id and approle_secret as an environment variable and use the modified mount point
            // approle_auth {
            //    approle_auth_mount_point = "my-approle-auth"    
            // }

            // If specify the approle_id and approle_secret as an environment variable and use the default mount point, set the empty structure.
            // approle_auth {}
        }
    }
```
