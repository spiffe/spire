# Server plugin: CredentialComposer "uniqueid"

The `uniqueid` plugin adds the `x509UniqueIdentifier` attribute to the X509-SVID subject for workloads. Server and agent X509-SVIDs are not modified.

The x509UniqueIdentifier is formed from a hash of the SPIFFE ID of the workload.

This plugin is intended for backwards compatibility for deployments that have come to rely on this attribute (introduced in SPIRE 1.4.2 and reverted in SPIRE 1.9.0).

This plugin has no configuration. To use the plugin, add it to the plugins section of the SPIRE Server configuration:

```hcl
plugins {
    CredentialComposer "uniqueid" {}

    // ... other plugins ...
}
```
