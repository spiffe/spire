# Upstream Authority "vault" Plugin

The vault plugin signs intermediate CA certificates for SPIRE using the Vault PKI Engine.
The plugin does not support the `PublishJWTKey` RPC and is therefore not appropriate for use in nested SPIRE topologies where JWT-SVIDs are in use.

## Configuration

The plugin accepts the following configuration options:

| key                  | type   | required | description                                                                                                | default              |
|:---------------------|:-------|:---------|:-----------------------------------------------------------------------------------------------------------|:---------------------|
| vault_addr           | string |          | The URL of the Vault server. (e.g., <https://vault.example.com:8443/>)                                     | `${VAULT_ADDR}`      |
| namespace            | string |          | Name of the Vault namespace. This is only available in the Vault Enterprise.                               | `${VAULT_NAMESPACE}` |
| pki_mount_point      | string |          | Name of the mount point where PKI secret engine is mounted                                                 | pki                  |
| ca_cert_path         | string |          | Path to a CA certificate file used to verify the Vault server certificate. Only PEM format is supported.   | `${VAULT_CACERT}`    |
| insecure_skip_verify | bool   |          | If true, vault client accepts any server certificates                                                      | false                |
| cert_auth            | struct |          | Configuration for the Client Certificate authentication method                                             |                      |
| token_auth           | struct |          | Configuration for the Token authentication method                                                          |                      |
| approle_auth         | struct |          | Configuration for the AppRole authentication method                                                        |                      |
| k8s_auth             | struct |          | Configuration for the Kubernetes authentication method                                                     |                      |

The plugin supports **Client Certificate**, **Token** and **AppRole** authentication methods.

- **Client Certificate** method authenticates to Vault using a TLS client certificate.
- **Token** method authenticates to Vault using the token in a HTTP Request header.
- **AppRole** method authenticates to Vault using a RoleID and SecretID that are issued from Vault.

The [`ca_ttl` SPIRE Server configurable](https://github.com/spiffe/spire/blob/main/doc/spire_server.md#server-configuration-file) should be less than or equal to the Vault's PKI secret engine TTL.
To configure the TTL value, tune the engine.

e.g.

```shell
$ vault secrets tune -max-lease-ttl=8760h pki
```

The configured token needs to be attached to a policy that has at least the following capabilities:

```hcl
path "pki/root/sign-intermediate" {
  capabilities = ["update"]
}
```

## Client Certificate Authentication

| key                   | type   | required | description                                                                                                          | default                |
|:----------------------|:-------|:---------|:---------------------------------------------------------------------------------------------------------------------|:-----------------------|
| cert_auth_mount_point | string |          | Name of the mount point where TLS certificate auth method is mounted                                                 | cert                   |
| cert_auth_role_name   | string |          | Name of the Vault role. If given, the plugin authenticates against only the named role. Default to trying all roles. |                        |
| client_cert_path      | string |          | Path to a client certificate file. Only PEM format is supported.                                                     | `${VAULT_CLIENT_CERT}` |
| client_key_path       | string |          | Path to a client private key file. Only PEM format is supported.                                                     | `${VAULT_CLIENT_KEY}`  |

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
            // If specify the role to authenticate with
            // cert_auth {
            //     cert_auth_mount_point = "test-tls-cert-auth"
            //     cert_auth_role_name = "test"
            //     client_cert_path = "/path/to/client-cert.pem"
            //     client_key_path  = "/path/to/client-key.pem"
            // }
       
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

| key   | type   | required | description                                     | default          |
|:------|:-------|:---------|:------------------------------------------------|:-----------------|
| token | string |          | Token string to set into "X-Vault-Token" header | `${VAULT_TOKEN}` |

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

| key                      | type   | required | description                                                      | default                      |
|:-------------------------|:-------|:---------|:-----------------------------------------------------------------|:-----------------------------|
| approle_auth_mount_point | string |          | Name of the mount point where the AppRole auth method is mounted | approle                      |
| approle_id               | string |          | An identifier of AppRole                                         | `${VAULT_APPROLE_ID}`        |
| approle_secret_id        | string |          | A credential of AppRole                                          | `${VAULT_APPROLE_SECRET_ID}` |

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

## Kubernetes Authentication

| key                  | type   | required | description                                                                       | default    |
|:---------------------|:-------|:---------|:----------------------------------------------------------------------------------|:-----------|
| k8s_auth_mount_point | string |          | Name of the mount point where the Kubernetes auth method is mounted               | kubernetes |
| k8s_auth_role_name   | string | ✔        | Name of the Vault role. The plugin authenticates against the named role           |            |
| token_path           | string | ✔        | Path to the Kubernetes Service Account Token to use authentication with the Vault |            |

```hcl
    UpstreamAuthority "vault" {
        plugin_data {
            vault_addr = "https://vault.example.org/"
            pki_mount_point = "test-pki"
            ca_cert_path = "/path/to/ca-cert.pem"
            k8s_auth {
               k8s_auth_mount_point = "my-k8s-auth"
               k8s_auth_role_name = "my-role"
               token_path = "/path/to/sa-token"
            }
            
            // If specify role name and use the default mount point and token_path
            // k8s_auth {
            //   k8s_auth_role_name = "my-role"
            // }            
        }
    }
```
