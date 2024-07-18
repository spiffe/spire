# Server plugin: UpstreamAuthority "ejbca"

The `ejbca` UpstreamAuthority plugin uses a connected [EJBCA](https://www.ejbca.org/) to issue intermediate signing certificates for the SPIRE server. The plugin can authenticate to EJBCA using mTLS (client certificate) or using the OAuth 2.0 "client credentials" token flow (sometimes called two-legged OAuth 2.0).

> The EJBCA UpstreamAuthority plugin uses only the `/ejbca-rest-api/v1/certificate/pkcs10enroll` REST API endpoint, and is compatible with both [EJBCA Community](https://www.ejbca.org/) and [EJBCA Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/).

## Requirements

* EJBCA [Community](https://www.ejbca.org/) or EJBCA [Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/)
  * The "REST Certificate Management" protocol must be enabled under System Configuration > Protocol Configuration.

> EJBCA Enterprise is required for the OAuth 2.0 "client credentials" token flow. EJBCA Community only supports mTLS (client certificate) authentication.

## Configuration

The EJBCA UpstreamAuthority Plugin accepts the following configuration options.

| Configuration              | Description                                                                                                                                                                                                                                  | Default from Environment Variables |
|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| `hostname`                 | The hostname of the connected EJBCA server.                                                                                                                                                                                                  |                                    |
| `ca_cert_path`             | (optional) The path to the CA certificate file used to validate the EJBCA server's certificate. Certificates must be in PEM format.                                                                                                          | `EJBCA_CA_CERT_PATH`               |
| `cert_auth`                | An object containing the fields described in [Client Certificate Authentication](#client-certificate-authentication). Required if Client Cert Auth is used.                                                                                  |                                    |
| `oauth`                    | An object containing the fields described in [OAuth 2.0 Authentication](#oauth-20-authentication). Required if OAuth 2.0 is used.                                                                                                            |                                    |
| `ca_name`                  | The name of a CA in the connected EJBCA instance that will issue the intermediate signing certificates.                                                                                                                                      |                                    |
| `end_entity_profile_name`  | The name of an end entity profile in the connected EJBCA instance that is configured to issue SPIFFE certificates.                                                                                                                           |                                    |
| `certificate_profile_name` | The name of a certificate profile in the connected EJBCA instance that is configured to issue intermediate CA certificates.                                                                                                                  |                                    |
| `end_entity_name`          | (optional) The name of the end entity, or configuration for how the EJBCA UpstreamAuthority should determine the end entity name. See [End Entity Name Customization](#ejbca-end-entity-name-customization-leaf-certificates) for more info. |                                    |
| `account_binding_id`       | (optional) An account binding ID in EJBCA to associate with issued certificates.                                                                                                                                                             |                                    |

> Configuration parameters that have an override from Environment Variables will always override the provided value from the SPIRE configuration with the values in the environment.
>
> If all configuration parameters for the selected auth method are specified by environment variables, an empty block still must exist to select the auth method.

### Client Certificate Authentication

| Configuration      | Description                                                                                                | Default from Environment Variables |
|--------------------|------------------------------------------------------------------------------------------------------------|------------------------------------|
| `client_cert_path` | The path to the client certificate (public key only) used to authenticate to EJBCA. Must be in PEM format. | `EJBCA_CLIENT_CERT_PATH`           |
| `client_key_path`  | The path to the client key matching `client_cert` used to authenticate to EJBCA. Must be in PEM format.    | `EJBCA_CLIENT_CERT_KEY_PATH`       |

```hcl
UpstreamAuthority "ejbca" {
    plugin_data {
        hostname = "ejbca.example.com"
        cert_auth {
            client_cert_path = "/path/to/client_cert.pem"
            client_key_path = "/path/to/client_key.pem"
        }
        ca_name = "Fake-Sub-CA"
        end_entity_profile_name = "fakeSpireIntermediateCAEEP"
        certificate_profile_name = "fakeSubCACP"
        ca_cert = <<EOF
-----BEGIN CERTIFICATE-----
MIIDE ... mn+GJf
-----END CERTIFICATE-----
EOF
        ca_name = "Sub-CA"
        end_entity_profile_name = "spireIntermediateCA"
        certificate_profile_name = "SUBCA"
        end_entity_name = ""
        account_binding_id = "abc123"
    }
}
```

### OAuth 2.0 Authentication

| Configuration   | Description                                                                           | Default from Environment Variables |
|-----------------|---------------------------------------------------------------------------------------|------------------------------------|
| `token_url`     | The OAuth 2.0 token URL used to obtain an access token.                               | `EJBCA_OAUTH_TOKEN_URL`            |
| `client_id`     | The OAuth 2.0 client ID used to obtain an access token.                               | `EJBCA_OAUTH_CLIENT_ID`            |
| `client_secret` | The OAuth 2.0 client secret used to obtain an access token.                           | `EJBCA_OAUTH_CLIENT_SECRET`        |
| `scopes`        | (optional) A comma-separated list of OAuth 2.0 scopes used to obtain an access token. | `EJBCA_OAUTH_SCOPES`               |
| `audience`      | (optional) The OAuth 2.0 audience used to obtain an access token.                     | `EJBCA_OAUTH_AUDIENCE`             |

```hcl
UpstreamAuthority "ejbca" {
    plugin_data {
        hostname = "ejbca.example.com"
        ca_cert_path = "/path/to/ca_cert.pem"
        oauth {
            token_url = "https://dev.idp.com/oauth/token"
            client_id = "<client_id>"
            client_secret = "<client_secret>"
        }
        ca_name = "Fake-Sub-CA"
        end_entity_profile_name = "fakeSpireIntermediateCAEEP"
        certificate_profile_name = "fakeSubCACP"
        end_entity_name = ""
        account_binding_id = "abc123"
    }
}
```

## EJBCA Sub CA End Entity Profile & Certificate Profile Configuration

The connected EJBCA instance must have at least one Certificate Profile and at least one End Entity Profile capable of issuing SPIFFE certificates. The Certificate Profile must be of type `Sub CA`, and must be able to issue certificates with the ECDSA prime256v1 algorithm, at a minimum. The SPIRE Server configuration may require additional fields.

The End Entity Profile must have the following Subject DN Attributes:

* `serialNumber, Serial number (in DN)` [modifiable]
* `O, Organization` [modifiable]
* `C, Country (ISO 3166)` [modifiable]

And the following Other Subject Attributes:

* `Uniform Resource Identifier (URI)` [modifiable]

## EJBCA End Entity Name Customization (leaf certificates)

The EJBCA UpstreamAuthority plugin allows users to determine how the End Entity Name is selected at runtime. Here are the options you can use for `end_entity_name`:

* **`cn`:** Uses the Common Name from the CSR's Distinguished Name.
* **`dns`:** Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **`uri`:** Uses the first URI from the CSR's Subject Alternative Names (SANs).
* **`ip`:** Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
* **Custom Value:** Any other string will be directly used as the End Entity Name.

By default, SPIRE issues certificates with no DN and only the SPIFFE ID in the SANs. If you want to use the SPIFFE ID as the End Entity Name, you can usually leave this field blank or set it to `uri`.

If the endEntityName field is not explicitly set, the EJBCA UpstreamAuthority plugin will attempt to determine the End Entity Name using the following default behavior:

* **First, it will try to use the Common Name:** It looks at the Common Name from the CSR's Distinguished Name.
* **If the Common Name is not available, it will use the first DNS Name:** It looks at the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **If the DNS Name is not available, it will use the first URI:** It looks at the first URI from the CSR's Subject Alternative Names (SANs).
* **If the URI is not available, it will use the first IP Address:** It looks at the first IP Address from the CSR's Subject Alternative Names (SANs).
* **If none of the above are available, it will return an error.
