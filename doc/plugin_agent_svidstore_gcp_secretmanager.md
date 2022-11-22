# Agent plugin: SVIDStore "gcp_secretmanager"

The `gcp_secretmanager` plugin stores in [Google cloud Secret Manager](https://cloud.google.com/secret-manager) the resulting X509-SVIDs of the entries that the agent is entitled to.

## Secret format

The format that is used to store in a secret the issued identity is the following:

```json
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

## Required GCP permissions

This plugin requires the following IAM permissions in order to function:

```text
secretmanager.secrets.create
secretmanager.secrets.delete
secretmanager.secrets.get
secretmanager.secrets.update
secretmanager.versions.add
```

Please note that this plugin does not require permission to read secret payloads stored on secret version.

## Configuration

| Configuration        | Description                                                                                                                                                 | DEFAULT                                                        |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------|
| service_account_file | (Optional) Path to the service account file used to authenticate with the Google Compute Engine API. By default credentials are retrieved from environment. | Value of `GOOGLE_APPLICATION_CREDENTIALS` environment variable |

A sample configuration:

```hcl
    SVIDStore "gcp_secretmanager" {
       plugin_data {
           service_account_file = "/opt/token"
       }
    }
```

## IAM Policy

It is possible to add an IAM Policy when creating a new secret. This is done using the `role` and `serviceaccount` selectors, which must be configured together.
The secret will have the inherited IAM Policy together with the new policy, with a single Binding created. The Binding will use the provided role together with service account as unique member.
In case that a role/serviceaccount is not set, the secret will use inherited policies from Secret Manager.

```yaml
bindings:
- members:
  - serviceAccount:test-secret@project-id.iam.gserviceaccount.com
  role: roles/secretmanager.viewer
```

## Store selectors

Selectors are used on `storable` entries to describe metadata that is needed by `gcp_secretmanager` in order to store secrets in Google Cloud Secret manager. In case that a `required` selector is not provided, the plugin will return an error at execution time.

| Selector                           | Example                                                                          | Required | Description                                                                |
|------------------------------------|----------------------------------------------------------------------------------|----------|----------------------------------------------------------------------------|
| `gcp_secretmanager:name`           | `gcp_secretmanager:secretname:some-name`                                         | x        | The secret name where SVID will be stored                                  |
| `gcp_secretmanager:projectid`      | `gcp_secretmanager:projectid:some-project`                                       | x        | The Google Cloud project ID which the plugin will use Secret Manager       |
| `gcp_secretmanager:role`           | `gcp_secretmanager:role:roles/secretmanager.viewer`                              | -        | The Google Cloud role id for IAM policy (serviceaccount required when set) |
| `gcp_secretmanager:serviceaccount` | `gcp_secretmanager:serviceaccount:test-secret@test-proj.iam.gserviceaccount.com` | -        | The Google Cloud Service account for IAM policy (role required when set)   |
