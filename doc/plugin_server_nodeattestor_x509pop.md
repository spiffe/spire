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

```xml
spiffe://<trust_domain>/spire/agent/x509pop/<fingerprint>
```

| Configuration         | Description                                                                                                                                                                                                                                    | Default                                 |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------|
| `ca_bundle_path`      | The path to the trusted CA bundle on disk. The file must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification. If the CA certificates are in more than one file, use `ca_bundle_paths` instead. |                                         |
| `ca_bundle_paths`     | A list of paths to trusted CA bundles on disk. The files must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification.                                                                             |                                         |
| `agent_path_template` | A URL path portion format of Agent's SPIFFE ID. Describe in text/template format.                                                                                                                                                              | `"{{ .PluginName}}/{{ .Fingerprint }}"` |

A sample configuration:

```hcl
    NodeAttestor "x509pop" {
        plugin_data {
            ca_bundle_path = "/opt/spire/conf/server/agent-cacert.pem"
            
            # Change the agent's SPIFFE ID format
            # agent_path_template = "/cn/{{ .Subject.CommonName }}"
        }
    }
```

## Selectors

| Selector         | Example                                                           | Description                                                                              |
|------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| Common Name      | `x509pop:subject:cn:example.org`                                  | The Subject's Common Name (see X.500 Distinguished Names)                                |
| SHA1 Fingerprint | `x509pop:ca:fingerprint:0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33` | The SHA1 fingerprint as a hex string for each cert in the PoP chain, excluding the leaf. |
| SerialNumber     | `x509pop:serialnumber:0a1b2c3d4e5f`                               | The leaf certificate serial number as a lowercase hexadecimal string                     |

## Agent Path Template

The agent path template is a way of customizing the format of generated SPIFFE IDs for agents.
The template formatter is using Golang text/template conventions, it can reference values provided by the plugin or in a [golang x509.Certificate](https://pkg.go.dev/crypto/x509#Certificate)

Some useful values are:

| Value                 | Description                                                                                  |
|-----------------------|----------------------------------------------------------------------------------------------|
| .PluginName           | The name of the plugin                                                                       |
| .Fingerprint          | The SHA1 fingerprint of the agent's x509 certificate                                         |
| .TrustDomain          | The configured trust domain                                                                  |
| .Subject.CommonName   | The common name field of the agent's x509 certificate                                        |
| .SerialNumberHex      | The serial number field of the agent's x509 certificate represented as lowercase hexadecimal |
