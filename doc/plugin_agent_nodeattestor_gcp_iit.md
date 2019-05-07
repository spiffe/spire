# Agent plugin: NodeAttestor "gcp_iit"

*Must be used in conjunction with the server-side gcp_iit plugin*

The `gcp_iit` plugin automatically attests instances using the [GCP Instance Identity Token](https://cloud.google.com/compute/docs/instances/verifying-instance-identity). It also allows an operator to use GCP Instance IDs when defining SPIFFE ID attestation policies.


| Configuration         | Description                                                                                                                        | Default                    |
| --------------------- | -----------------------------------------------------------------------------------------------------------------------------------| -------------------------- |
| identity_token_host  | Host where an [identity token](https://cloud.google.com/compute/docs/instances/verifying-instance-identity) can be retrieved from | `metadata.google.internal` |
| service_account       | The service account to fetch an identity token from                                                                                | `default`                  |

A sample configuration:

```
    NodeAttestor "gcp_iit" {
        plugin_data {
            identity_token_host = "metadata.google.internal"
            service_account = "XXX@developer.gserviceaccount.com"
        }
    }
