# Agent plugin: NodeAttestor "k8s"

*Must be used in conjunction with the server-side k8s plugin*

The `k8s` plugin retrieves an identity document from Kubernetes API Server and
uses it to prove its identity to a SPIRE server and receive a SVID.
The identity document consists of a x509 certificate signed by the Kubernetes
API Server Certificate Authority. The plugin owns the private key associated
with the identity document and is able to respond to proof-of-possession
challenges issued by the server plugin.

In order to retrieve the identity document, the plugin needs user credentials
to access the Kubernetes API Server and submit a Certificate Signing Request (CSR).
The credentials consist of a private key and a certificate stored on disk.
It also needs a root certificate to validate the TLS certificate presented 
by the Kubernetes API Server.

The CSRs issued by the plugin follow the format used by Kubernetes Node Authorizer.
They are automatically approved if the correct RBAC roles and bindings are in place.
Alternatively, they can be approved manually by the Kubernetes administrator using
the command `kubectl certificate approve`

The SPIFFE ID produced by the plugin is based on the common name of the certificate
and is in the form:

```
spiffe://<trust domain>/spire/agent/k8s/system/node/<host name>
```

See this [design document](https://docs.google.com/document/d/14PFWpKHbXLxJwPn9NYYcUWGyO9d8HE1H_XAZ4Tz5K0E)
for more details.

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| `trust_domain`  |  The trust domain that the node belongs to. |  |
| `k8s_private_key_path` | The path to the private key on disk (PEM encoded PKCS1 or PKCS8) used to authenticate the agent to the Kubernetes API Server| |
| `k8s_certificate_path` | The path to the certificate bundle on disk. Used to authenticate the agent to the Kubernetes API Server | |
| `k8s_ca_certificate_path` | The root certificate used to validate the certificate presented by the Kubernetes API Server | |
| `kubeconfig_path` | Optional. The path to the kubeconfig file containing Kubernetes cluster access information. If not provided, the plugin tries the paths listed in the environment variable KUBECONFIG. If KUBECONFIG is not set, the plugin tries the default location $HOME/.kube/config | |
