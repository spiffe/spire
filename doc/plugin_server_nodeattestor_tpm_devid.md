# Server plugin: NodeAttestor "tpm_devid"

*Must be used in conjunction with the agent-side tpm_devid plugin*

The `tpm_devid` plugin attests nodes that own a TPM
and that have been provisioned with a DevID certificate through an out-of-band
mechanism.

The plugin issues two challenges to the agent:

1. A proof-of-possession challenge: This is required to verify the node is in
possession of the private key that corresponds to the DevID certificate.
Additionally, the server verifies that the DevID certificate is rooted to
a trusted set of CAs.

2. A proof-of-residency challenge: This is required to prove that the DevID
key pair was generated and resides in a TPM. Additionally, the server verifies
that the TPM is authentic by verifying that the endorsement certificate is
rooted to a trusted set of manufacturer CAs.

The SPIFFE ID produced by the plugin is based on the certificate fingerprint,
where the fingerprint is defined as the SHA1 hash of the ASN.1 DER encoding of
the identity certificate.

The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/tpm_devid/<fingerprint>
```

| Configuration           | Description                                                                                                                                                                                       | Default |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `devid_ca_path`         | The path to the trusted CA certificate(s) on disk to use for DevID validation. The file must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification. |         |
| `endorsement_ca_path`   | The path to the trusted manufacturer CA certificate(s) on disk. The file must contain one or more PEM blocks forming the set of trusted manufacturer CA's for chain-of-trust verification.        |         |

A sample configuration:

```hcl
    NodeAttestor "tpm_devid" {
        plugin_data {
            devid_ca_path = "/opt/spire/conf/server/devid-cacert.pem"
            endorsement_ca_path = "/opt/spire/conf/server/endorsement-cacert.pem"
        }
    }
```

## Selectors

| Selector                    | Example                                                           | Description                                                                              |
|-----------------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| Subject common name         | `tpm_devid:subject:cn:example.org`                                | The subject's common name.                                                               |
| Issuer common name          | `tpm_devid:issuer:cn:authority.org`                               | The issuer's common name.                                                                |
| SHA1 fingerprint            | `tpm_devid:fingerprint:9ba51e2643bea24e91d24bdec3a1aaf8e967b6e5`  | The SHA1 fingerprint as a hex string for each cert in the PoP chain, excluding the leaf. |
