# Server plugin: UpstreamAuthority "cert-manager"

The `cert-manager` plugin uses an instance of
[cert-manager](https://cert-manager.io) running in Kubernetes to to request
intermediate signing certificates for SPIRE Server.

This plugin will request a signing certificate from cert-manager via a
[CertificateRequest](https://cert-manager.io/docs/concepts/certificaterequest/)
resource. Once the referenced issuer has signed the request,

# Considerations
This plugin requires access to a Kubernetes cluster running cert-manager and
create CertificateRequests.

Only issuers that have support for providing signing certificates are supported.

# Configuration
This plugin requests certificates from the configured
[cert-manager](https://cert-manager.io/docs/configuration/) issuer.

| Configuration             | Description                                                       |
| ------------------------- | ----------------------------------------------------------------- |
| kube_config_path          | Path to the kubeconfig used to connect to the Kubernetes cluster. |
| namespace                 | The namespace to create CertificateRequests for signing.          |
| issuer_name               | The name of the issuer to reference in CertificateRequests.       |
| issuer_kind               | (Optional) The kind of the issuer to reference in CertificateRequests. Defaults to "Issuer" if empty. |
| issuer_group              | (Optional) The group of the issuer to reference in CertificateRequests. Defaults to "cert-manager.io" if empty. |


```hcl
UpstreamAuthority "cert-manager" {
    plugin_data {
        issuer_name = "spire-ca"
        issuer_kind = "Issuer"
        issuer_group = "cert-manager.io"
        namespace = "sandbox"
        kube_config_path = "/etc/kubernetes/kubeconfig"
    }
}
```
