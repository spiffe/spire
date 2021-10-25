# Agent plugin: SVIDStore "gcloud_secretmanager"

The `gcloud_secretmanager` plugin stores in [gcloud Secret Manager](https://cloud.google.com/secret-manager) the resulting X509-SVIDs of the entries that the agent is entitled to. 

### Secret format

The format that is used to store in a secret the issued identity is the following:

```
{
	"spiffeId": "spiffe://example.org",
	"x509Svid": "X509_CERT_CHAIN_PEM",
	"x509SvidKey": "PRIVATE_KET_PEM",
	"bundle": "X509_BUNDLE_PEM",
	"federatedBundles": {
		"spiffe://federated.org": "X509_FEDERATED_BUNDLE_PEM"
	}
}
```

### Configuration

| Configuration      | Description |
| ------------------ | ----------- |
| service_account_file      |  Path to the service account file used to authenticate with the Google Compute Engine API. |

A sample configuration:

```
    SVIDStore "gcloud_secretmanager" {
       plugin_data {
           service_account_file = "/opt/token"
       }
    }
```

### Store selectors

The selectors of the type `gcloud_secretmanager` are used to describe metadata that is needed by the plugin in order to store secret values in gcloud Secret Manager.

| Selector                               | Example                                           | Description                                  |
| -------------------------------------- | ------------------------------------------------- | -------------------------------------------- |
| `gcloud_secretmanager:secretname`      | `gcloud_secretmanager:secretname:some-name`       | The secrets name where SVID will be stored   |
| `gcloud_secretmanager:secretproject`   | `gcloud_secretmanager:secretproject:some-project` | The GCloud project that contains secrets     |

