# Server plugin: NodeAttestor "x509pop"

*Must be used in conjunction with the agent-side x509pop plugin*

The `x509pop` plugin attests nodes that have been provisioned with an x509
identity through an out-of-band mechanism. It verifies that the certificate is
rooted to a trusted set of CAs and issues a signature-based proof-of-possession
challenge to the agent plugin to verify that the node is in possession of the
private key.

The SPIFFE ID produced by the plugin is based on the certificate fingerprint,
where the fingerprint is defined as the SHA1 hash of the ASN.1 DER encoding of
the identity certificate. The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/x509pop/<fingerprint>
```

| Configuration         | Description                                                                                                                                                                                                                                    | Default                                 |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| `mode`                | If `spiffe`, use the spire servers own trust bundle to use for validation. If `external_pki`, use the specified CA(s).                                                                                                                         | external_pki                                                    |
| `svid_prefix`            | The prefix of the SVID to use for matching valid SVIDS and exchanging them for Node SVIDs                                                                                                                                                   | /spire-exchange                                                 |
| `ca_bundle_path`      | The path to the trusted CA bundle on disk. The file must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification. If the CA certificates are in more than one file, use `ca_bundle_paths` instead. |                                                                 |
| `ca_bundle_paths`     | A list of paths to trusted CA bundles on disk. The files must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification.                                                                             |                                                                 |
| `agent_path_template` | A URL path portion format of Agent's SPIFFE ID. Describe in text/template format.                                                                                                                                                              | See [Agent Path Template](#agent-path-template) for details   |

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

| Selector         | Example                                                           | Description                                                                                                                                                                                                |
|------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Common Name      | `x509pop:subject:cn:example.org`                                  | The Subject's Common Name (see X.500 Distinguished Names)                                                                                                                                                  |
| SHA1 Fingerprint | `x509pop:ca:fingerprint:0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33` | The SHA1 fingerprint as a hex string for each cert in the PoP chain, excluding the leaf.                                                                                                                   |
| SerialNumber     | `x509pop:serialnumber:0a1b2c3d4e5f`                               | The leaf certificate serial number as a lowercase hexadecimal string                                                                                                                                       |
| San              | `x509pop:san:<key>:<value>`                                       | The san selectors on the leaf certificate. The expected format of the uri san is `x509pop://<trust_domain>/<key>/<value>`. One selector is exposed per uri san corresponding to x509pop uri scheme. string |

## SVID Path Prefix

When `mode="spiffe"` the SPIFFE ID being exchanged must be prefixed by the specified `svid_prefix`. The prefix will be removed from the `.SVIDPathTrimmed` property before sending to the agent path template. If `svid_prefix` is set to `""`, all prefixes will be allowed, and the limiting logic will have to be implemented in the `agent_path_template`.

**Example:** If your trust domain is example.com and `svid_prefix` is set to its default value `/spire-exchange`, and [agent_path_template](#agent-path-template) is the default too, then the SPIFFE ID from the x509 identity `spiffe://example.com/spire-exchange/testhost` will be exchanged for `spiffe://example.com/spire/agent/x509pop/testhost`. If a SPIFFE ID with a different prefix is given, for example `spiffe://example.com/other/testhost`, it will not match the `svid_prefix` and will be rejected.

## Agent Path Template

Specifying the value of `agent_path_template` provides a way of customizing the format of generated SPIFFE IDs for agents. The default format for every mode is shown below

| `mode`         | `agent_path_template`                      |
|----------------|--------------------------------------------|
| `spiffe`       | `{{ .PluginName }}/{{ .SVIDPathTrimmed }}` |
| `external_pki` | `{{ .PluginName }}/{{ .Fingerprint }}`     |

The template formatter is using Golang text/template conventions. It can reference values provided by the plugin or in a [golang x509.Certificate](https://pkg.go.dev/crypto/x509#Certificate).
Details about the template engine are available [here](template_engine.md).

Some useful values are:

| Value                 | Description                                                                                  |
|-----------------------|----------------------------------------------------------------------------------------------|
| .PluginName           | The name of the plugin                                                                       |
| .Fingerprint          | The SHA1 fingerprint of the agent's x509 certificate                                         |
| .TrustDomain          | The configured trust domain                                                                  |
| .Subject.CommonName   | The common name field of the agent's x509 certificate                                        |
| .SerialNumberHex      | The serial number field of the agent's x509 certificate represented as lowercase hexadecimal |
| .SVIDPathTrimmed      | The SVID Path after trimming off the SVID prefix                                             |
