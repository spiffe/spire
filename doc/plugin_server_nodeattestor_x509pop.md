# Server plugin: NodeAttestor "x509pop"

*Must be used in conjunction with the [agent-side x509pop plugin](plugin_agent_nodeattestor_x509pop.md)*

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

| Configuration         | Description                                                                                                                                                                                                                                    | Default                                                        |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `mode`                | If `spiffe`, use the spire servers own trust bundle to use for validation. If `external_pki`, use the specified CA(s).                                                                                                                         | external_pki                                                   |
| `svid_prefix`         | The prefix of the SVID to use for matching valid SVIDS and exchanging them for Node SVIDs                                                                                                                                                      | /spire-exchange                                                |
| `ca_bundle_path`      | The path to the trusted CA bundle on disk. The file must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification. If the CA certificates are in more than one file, use `ca_bundle_paths` instead. |                                                                |
| `ca_bundle_paths`     | A list of paths to trusted CA bundles on disk. The files must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification.                                                                             |                                                                |
| `agent_path_template` | A URL path portion format of Agent's SPIFFE ID. Describe in text/template format.                                                                                                                                                              | See [Agent Path Template](#agent-path-template) for details    |
| `max_intermediates`   | Maximum number of intermediate certificates allowed in the certificate chain. This limit helps prevent resource exhaustion attacks.                                                                                                            | 4                                                              |
| `max_rsa_key_size`    | Maximum RSA key size in bits allowed in certificates. This limit helps prevent resource exhaustion attacks from excessively large keys.                                                                                                        | 8192                                                           |
| `verify_client_ip`    | If `true`, validates the connecting peer's IP against the leaf certificate's IP SANs. Attestation fails if no SAN matches. Reflects the immediate peer - may not represent true client origin behind load balancers.                           | false                                                          |
| `group_template`      | Go text/template used to derive one or more group values from the certificate. If empty, no group selector is produced. See [Group Template](#group-template).                                                                                 |                                                                |
| `groups`              | Allowlist of group values that may be emitted as selectors. A group produced by `group_template` must be in this list to be emitted. Required when `group_template` is set.                                                                    |                                                                |

A sample configuration:

```hcl
    NodeAttestor "x509pop" {
        plugin_data {
            ca_bundle_path = "/opt/spire/conf/server/agent-cacert.pem"

            # Change the agent's SPIFFE ID format
            # agent_path_template = "/cn/{{ .Subject.CommonName }}"

            # Optional: Maximum number of intermediate certificates (default: 4)
            # max_intermediates = 4

            # Optional: Maximum RSA key size in bits (default: 8192)
            # max_rsa_key_size = 8192
        }
    }
```

## Selectors

| Selector         | Example                                                           | Description                                                                                                                                                                                                          |
|------------------|-------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Common Name      | `x509pop:subject:cn:example.org`                                  | The Subject's Common Name (see X.500 Distinguished Names)                                                                                                                                                            |
| SHA1 Fingerprint | `x509pop:ca:fingerprint:0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33` | The SHA1 fingerprint as a hex string for each cert in the PoP chain, excluding the leaf.                                                                                                                             |
| SerialNumber     | `x509pop:serialnumber:0a1b2c3d4e5f`                               | The leaf certificate serial number as a lowercase hexadecimal string                                                                                                                                                 |
| San              | `x509pop:san:<key>:<value>`                                       | The san selectors on the leaf certificate. The expected format of the uri san is `x509pop://<trust_domain>/<key>/<value>`. One selector is exposed per uri san corresponding to x509pop uri scheme. string           |
| Group            | `x509pop:group:/cluster/foo/identity-exchange`                    | A group derived from `group_template`. Only emitted when the derived value is in `groups`. One selector is emitted per group. See [Group Template](#group-template).                                                 |

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
Details about the template engine are available in the [template engine documentation](template_engine.md).

Some useful values are:

| Value                       | Description                                                                                  |
|-----------------------------|----------------------------------------------------------------------------------------------|
| .PluginName                 | The name of the plugin                                                                       |
| .Fingerprint                | The SHA1 fingerprint of the agent's x509 certificate                                         |
| .TrustDomain                | The configured trust domain                                                                  |
| .Subject.CommonName         | The common name field of the agent's x509 certificate                                        |
| .SerialNumberHex            | The serial number field of the agent's x509 certificate represented as lowercase hexadecimal |
| .SVIDPathTrimmed            | The SVID Path after trimming off the SVID prefix                                             |
| .URISanSelectors.&lt;key&gt;| The value of the URI San selector with key `<key>`                                           |

## Group Template

Specifying `group_template` provides a way of deriving one or more group
values from the attesting certificate, which are emitted as
`x509pop:group:<value>` node selectors. It works in both modes and is hydrated
with the same values as the [agent path template](#agent-path-template), except
that `.SVIDPathTrimmed` is only populated when `mode = "spiffe"`.

The main use for this is node aliasing. Rather than creating an entry per agent,
create a single node alias parented to the server and selected on the group,
then parent workload entries to the alias:

```bash
spire-server entry create \
    -node \
    -spiffeID spiffe://example.org/cluster/foo \
    -selector x509pop:group:/cluster/foo/identity-exchange
```

The selector value comes from a template, and selector values are not otherwise
validated, so the `groups` allowlist rather than the template is what bounds
which groups a node can claim. It is required for that reason.

### Rendering more than one group

If the rendered output starts with `[` and ends with `]` it is parsed as a JSON
array of strings, and one selector is emitted per allowed element. Anything else
is treated as a single group value. Surrounding whitespace is trimmed before
either interpretation, and duplicate groups are emitted once.

In addition to the [template engine](template_engine.md) functions, the group
path template can use `toJson`, which makes rendering a list straightforward:

```hcl
    # A single group
    group_template = "{{ .SVIDPathTrimmed }}"

    # Several groups
    group_template = "{{ list .SVIDPathTrimmed \"all-nodes\" | toJson }}"

    # Equivalent, written as literal JSON
    group_template = "[\"{{ .SVIDPathTrimmed }}\", \"all-nodes\"]"

    groups = ["/cluster/foo/identity-exchange", "all-nodes"]
```

### When a group can not be derived

| Result                                                        | Effect                                                              |
|---------------------------------------------------------------|---------------------------------------------------------------------|
| A group that is not in `groups`                               | No selector for that group. Logged at debug level.                  |
| Empty output, or an empty JSON array                          | No group selector. Logged at debug level.                           |
| The template fails to execute                                 | No group selector. Attestation still succeeds, logged at debug.     |
| `fail "reason"`                                               | **Attestation is denied.** The reason is logged, not returned.      |
| Output shaped like a JSON array that can not be parsed        | **Attestation is denied.** The parse error is logged, not returned. |

Template execution failures are not fatal because a template may legitimately
not apply to every certificate. For example, referencing
`.URISanSelectors.datacenter` fails on a certificate without that URI SAN, and
making that fatal would prevent such nodes from attesting at all. Guard those
cases in the template instead, and the node simply gets no group:

```hcl
    group_template = "{{ if hasKey .URISanSelectors \"datacenter\" }}{{ .URISanSelectors.datacenter }}{{ end }}"
```

Use `fail` when a certificate should be rejected outright rather than left
without a group:

```hcl
    group_template = "{{ if hasKey .URISanSelectors \"datacenter\" }}{{ .URISanSelectors.datacenter }}{{ else }}{{ fail \"certificate has no datacenter SAN\" }}{{ end }}"
```

A denied node receives a generic error. The reason given to `fail` is only
written to the server log, since it is operator authored and the node has not
been admitted. Bear in mind that agents reattest, so a template that denies a
node also denies agents that are already running.
