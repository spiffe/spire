# Agent plugin: SVIDStore "gcp_secretmanager"

The `gcp_secretmanager` plugin stores in [Google cloud Secret Manager](https://cloud.google.com/secret-manager) the resulting X509-SVIDs of the entries that the agent is entitled to. 

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

### Required GCP permissions

In order to exercise plugin capabilities, IAM must contains following permissions 
```
secretmanager.secrets.create
secretmanager.secrets.delete
secretmanager.secrets.get
secretmanager.secrets.update
secretmanager.versions.add
```
Plugin never access to Secret versions that contains payloads.

### Configuration

| Configuration        | Description |
| -------------------- | ----------- |
| service_account_file | (Optional) Path to the service account file used to authenticate with the Google Compute Engine API. By default credentails are retrieved from environment. |

A sample configuration:

```
    SVIDStore "gcp_secretmanager" {
       plugin_data {
           service_account_file = "/opt/token"
       }
    }
```

### Store selectors

Selectors are used on `storable` entries to describre metadata that is needed by `gcp_secretmanager` in order to store secrets in Google cloud Secret manager. In case that a `required` selector is not provided the plugin will return an error on execution time. 

| Selector                      | Example                                    | Required | Description                                    |
| ----------------------------- | ------------------------------------------ | -------- | --------------------------------------------   |
| `gcp_secretmanager:name`      | `gcp_secretmanager:secretname:some-name`   | x        | The secrets name where SVID will be stored     |
| `gcp_secretmanager:projectid` | `gcp_secretmanager:projectid:some-project` | x        | The Google Cloud project that contains secrets |

