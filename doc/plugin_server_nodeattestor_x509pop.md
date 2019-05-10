# Server plugin: NodeAttestor "x509pop"

*Must be used in conjunction with the agent-side x509pop plugin*

The `x509pop` plugin attests nodes that have been provisioned with an x509
identity through an out-of-band mechanism. It verifies that the certificate is
rooted to a trusted set of CAs and issues a signature based proof-of-possession
challenge to the agent plugin to verify that the node is in possession of the
private key.

The SPIFFE ID produced by the plugin is based on the certificate fingerprint,
where the fingerprint is defined as the SHA1 hash of the ASN.1 DER encoding of
the identity certificate. The SPIFFE ID has the form:

```
spiffe://<trust domain>/spire/agent/x509pop/<fingerprint>
```

| Configuration | Description | Default                 |
| ------------- | ----------- | ----------------------- |
| `ca_bundle_path` | The path to the trusted CA bundle on disk. The file must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification. | |

A sample configuration:

```
	NodeAttestor "x509pop" {
		plugin_data {
			ca_bundle_path = "/opt/spire/conf/server/agent-cacert.pem"
		}
	}
```

## Selectors

| Selector            | Example                                                   | Description                                                           |
| ------------------- | --------------------------------------------------------- | --------------------------------------------------------------------- |
| Common Name         | `subject:cn:example.org`                                  | The Subject's Common Name (see X.500 Distinguished Names)             |
| SHA1 Fingerprint    | `ca:fingerprint:0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33` | The SHA1 fingerprint as a hex string for each cert in the PoP chain, excluding the leaf.  |
