# Agent plugin: SVIDStore "gcloud_secretsmanager"

The `gcloud_secretsmanager` plugin automatically stores X509-SVIDs as a marshalled [workload.X509SVIDResponse](https://github.com/spiffe/go-spiffe/blob/master/v2/proto/spiffe/workload/workload.proto#L10), 
in [gcloud Secret Manager](https://cloud.google.com/secret-manager), in latest secret version payload.

| Configuration      | Description |
| ------------------ | ----------- |
| service_account_file      |  Path to the service account file used to authenticate with the Google Compute Engine API. |

A sample configuration:

```
    SVIDStore "aws_secretsmanager" {
       plugin_data {
           service_account_file = "/opt/token"
       }
    }
```

### Store selectors

Selectors are used as a source for information about AWS Secret. And a Secret is created or updated to keep it updated with latests X509-SVID.

| Selector                        | Example                                   | Description                                    |
| ------------------------------- | ----------------------------------------- | ---------------------------------------------- |
| `gcloud_secretsmanager:secretname` | `gcloud_secretsmanager:secretname:some-name` | The secrets name where SVID will be stored |
| `gcloud_secretsmanager:secretproject`        | `gcloud_secretsmanager:secretproject:some-project`         | The GCloud project that contains secrets |

