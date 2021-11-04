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

This plugin requires the following IAM permissions in order to function:
```
secretmanager.secrets.create
secretmanager.secrets.delete
secretmanager.secrets.get
secretmanager.secrets.update
secretmanager.versions.add
```
Please note that this plugin does not require permission to read secret payloads stored on secret version.

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
| `gcp_secretmanager:roles`     | `gcp_secretmanager:roles:roles/secretmanager.viewer` | -        | The Google Cloud role id for IAM policy |
| `gcp_secretmanager:serviceaccount` | `gcp_secretmanager:serviceaccount:test-secret@test-proj.iam.gserviceaccount.com` | -        | The Google Cloud Service account for IAM policy |
| `gcp_secretmanager:user` | `gcp_secretmanager:user:user1@example.com` | -        | The Google Cloud user for IAM policy |
| `gcp_secretmanager:group` | `gcp_secretmanager:group:group1@example.com` | -        | The Google Cloud group for IAM policy |
| `gcp_secretmanager:domain` | `gcp_secretmanager:domain:somedomain.com` | -        | The Google Cloud domain for IAM policy |

