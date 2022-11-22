# Server plugin: UpstreamAuthority "gcp_cas"

The `gcp_cas` plugin uses the Certificate Authority from Google Cloud Platform, known as "Certificate Authority Service" (CAS),
 to generate intermediate signing certificates for SPIRE Server.

## Configuration

The plugin has a mandatory root_cert_spec section. It is used to specify which CAs are used for signing
 intermediate CAs as well as being part of the trusted root bundle. If it matches multiple CAs,
 the earliest expiring CA is used for signing.

"root_cert_spec" requires the following attributes:

| Configuration | Description                                                                  |
|---------------|------------------------------------------------------------------------------|
| project_name  | Project in GCP that has the root CA certificate                              |
| region_name   | The name of the region within GCP                                            |
| ca_pool       | The name of the CA Pool that has the root CA certificate                     |
| label_key     | Label key - value pair is used to filter and select the relevant certificate |
| label_value   | Label key - value pair is used to filter and select the relevant certificate |

### Sample configuration

```yaml
UpstreamAuthority "gcp_cas" {
    plugin_data {
        root_cert_spec {
            project_name = "MyProject"
            region_name = "us-central1"
            ca_pool = "mypool"
            label_key = "myapp-identity-root"
            label_value = "true"
        }
    }
}
```

## What does the plugin do

The plugin retrieves the CAs in GCPs that are in ENABLED state and match the root cert spec parameters specified
 in the plugin configuration. Among the matching certificates, the CA with the earliest expiry time is selected and
 used to create and sign an intermediate CA. The trust bundle contains the root CAs of all the CAs in GCP that matched
 the root_cert_spec label

## CA Rotation

* Steady state: Config label matches CA X and CA Y in CAS; plugin has been signing with CA X and all agents are trusting CA X and CA Y.
* Now create CA Z with the same label in CAS.
* Disable and optionally delete CA X in CAS.
* The plugin returns Y and Z's root certificates as UpstreamX509Roots. It also signs the issuing CA with Y which is now the earliest expiring CA.
* This doesn't impact existing workloads because they have been trusting Y even before SPIRE started to sign with Y.

## Authentication with Google Cloud Platform

This plugin connects and authenticates with Google Cloud Platform's CAS implicitly using Application Default Credentials (ADC).
 The ADC mechanism is documented at <https://cloud.google.com/docs/authentication/production#automatically>.

>ADC looks for service account credentials in the following order:
>
>1. If the environment variable GOOGLE_APPLICATION_CREDENTIALS is set, ADC uses the service account file that the variable points to.
>1. If the environment variable GOOGLE_APPLICATION_CREDENTIALS isn't set, ADC uses the service account that is attached to the resource that is running your code.
>1. If the environment variable GOOGLE_APPLICATION_CREDENTIALS isn't set, and there is no service account attached to the resource that is running your code, ADC uses the default service account that Compute Engine, Google Kubernetes Engine, App Engine, Cloud Run, and Cloud Functions provide.
>1. If ADC can't use any of the above credentials, an error occurs.
