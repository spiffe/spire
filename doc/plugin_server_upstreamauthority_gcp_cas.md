# Server plugin: UpstreamAuthority "gcp_cas"

The `gcp_cas` plugin uses Certificate Authority from Google Cloud Platform ( GCP )'s Certificate Authority Service ( CAS ) 
to generate intermediate signing certificates for SPIRE Server.

# Considerations
This plugin relies on GCP Certificate Authority Service which is currently in Beta. So please do not use this plugin in production

# Configuration
The plugin accepts the following configuration options:

| Configuration                 | Description                                                       |
| ----------------------------- | ----------------------------------------------------------------- |
| root_cert_spec.project_name   | Project in GCP that has the root CA certificate                   |
| root_cert_spec.region_name    | The name of the region within GCP                                 |
| root_cert_spec.label_key      | Label key - value pair is used to filter and select the relevant certificate  |
| root_cert_spec.label_value    | Label key - value pair is used to filter and select the relevant certificate  |
| trusted_root_spec             | ( Optional ) Array of entries containing project_name, region_name, label_key and label_value as described in root_cert_spec  |


##Sample configuration:

```yaml
UpstreamAuthority "gcp_cas" {
    plugin_data {
        project_name = "MyProject"         
        region_name = "us-central1"
        label_key = "myapp-identity-root"
        label_value = "true"        
    }
}
```
# What does the plugin do
The plugin retrieves the CAs in GCPs that are in Enabled state and match the root cert spec parameters specified
 in the plugin configuration. Among the matching certificates, the CA with the earliest expiry time is selected and
 used to create and sign an intermediate CA. The trust bundle contains all the CAs that matched the root_cert_spec label
 as well as the trusted_root_spec label

# CA Rotation
* Steady state: Config label matches CA X and CA Y in CAS; plugin has been signing with CA X and all agents are trusting CA X and CA Y
* Now create CA Z with the same label in CAS
* Disable and optionally delete CA X in CAS
* This builds a new trust bundle with Y and Z's root certificates and signs the issuing CA with Y which is now the earliest expiring CA
* This doesn't impact existing workloads because they have been trusting Y even before we started to sign with Y
