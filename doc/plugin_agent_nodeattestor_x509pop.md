# Agent plugin: NodeAttestor "x509pop"

*Must be used in conjunction with the server-side x509pop plugin*

The `x509pop` plugin provides attestation data for a node that has been
provisioned with an x509 identity through an out-of-band mechanism and responds
to a signature based proof-of-possession challenge issued by the server
plugin.

The SPIFFE ID produced by the server-side `x509pop` plugin is based on the certificate fingerprint, where the fingerprint is defined as the
SHA1 hash of the ASN.1 DER encoding of the identity certificate. The SPIFFE ID has the form:

```
spiffe://<trust domain>/spire/agent/x509pop/<fingerprint>
```

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| `private_key_path` | The path to the private key on disk (PEM encoded PKCS1 or PKCS8) | |
| `certificate_path` | The path to the certificate bundle on disk. The file must contain one or more PEM blocks, starting with the identity certificate followed by any intermediate certificates necessary for chain-of-trust validation. | |
| `intermediates_path` | Optional. The path to a chain of intermediate certificates on disk. The file must contain one or more PEM blocks, corresponding to intermediate certificates necessary for chain-of-trust validation. If the file pointed by `certificate_path` contains more than one certificate, this chain of certificates will be appended to it. | |

A sample configuration:

```
	NodeAttestor "x509pop" {
		plugin_data {
			private_key_path = "/opt/spire/conf/agent/agent.key.pem"
			certificate_path = "/opt/spire/conf/agent/agent.crt.pem"
		}
	}
```
