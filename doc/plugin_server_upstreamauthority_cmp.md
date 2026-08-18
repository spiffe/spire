# Server plugin: UpstreamAuthority "cmp"

The `cmp` UpstreamAuthority plugin obtains a certificate for the SPIRE server from an upstream certification authority (CA) using the Certificate Management Protocol (CMP), as defined in [RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) and updated by [RFC 9480](https://www.rfc-editor.org/rfc/rfc9480).

The plugin does not sign anything itself. It takes the certificate signing request (CSR) handed to it by SPIRE, packages that CSR into a CMP certification request, sends it to the upstream CA, and returns the certificate issued by that CA.

Because the request carries a PKCS #10 CSR ([RFC 2986](https://www.rfc-editor.org/rfc/rfc2986)), the CMP message body used is `p10cr` (the PKCS #10 certification request body, `PKIBody` choice `[4]`). This is the CMP enrollment flow profiled as "Enrolling an End Entity Using a PKCS #10 Request" in the Lightweight CMP Profile, [RFC 9483](https://www.rfc-editor.org/rfc/rfc9483#section-4.1.4).

This implementation is currently a stub. It provides the minimal plugin wiring required for SPIRE to recognize, configure, and load the plugin, but it does not yet perform any CMP exchange with an upstream CA.

## Current status

- Configuration is parsed and validated.
- The plugin is registered as a built-in upstream authority.
- `MintX509CAAndSubscribe` returns an `Unimplemented` gRPC status.
- JWT key publication and local bundle subscription remain unsupported.

## Intended operation

The intended request flow is:

1. SPIRE calls the plugin with a CSR for the certificate it needs.
2. The plugin builds a CMP `PKIMessage` whose body is a `p10cr` containing that CSR, and protects the message using the configured client certificate and key.
3. The plugin transfers the message to the upstream CA. HTTP transfer is defined in [RFC 6712](https://www.rfc-editor.org/rfc/rfc6712) (as updated by RFC 9480): the DER-encoded `PKIMessage` is sent as the body of an HTTP `POST` using the media type `application/pkixcmp`.
4. The CA answers with a certification response (`cp`). Per [RFC 9480, Section 2.9](https://www.rfc-editor.org/rfc/rfc9480#section-2.9), a `p10cr` carries no `certReqId`, so the `certReqId` in the corresponding `cp` is set to `-1`.
5. On a positive status (`accepted` or `grantedWithMods`), the plugin extracts the issued certificate from `certifiedKeyPair.certOrEncCert.certificate` and its chain from the message's `extraCerts` field, and returns them to SPIRE. On `rejection`, the `PKIStatusInfo` is surfaced as an error.

Protocol behaviors that a full implementation has to account for:

- **Certificate confirmation.** Unless the CA grants `implicitConfirm`, the enrollment is not complete until the client sends a `certConf` message and receives a `pkiConf` back. Depending on policy, a CA may revoke the freshly issued certificate if the confirmation does not arrive in time.
- **Delayed delivery.** A CA or registration authority may answer with status `waiting`, in which case the client polls with `pollReq` and waits at least `checkAfter` seconds between attempts until the final response arrives.

## Configuration

The plugin accepts the following configuration options:

| Configuration          | Description                                                                            | Default |
|------------------------|----------------------------------------------------------------------------------------|---------|
| `hostname`             | Hostname of the upstream CMP endpoint (CA or registration authority) requests are sent to. |         |
| `ca_cert_path`         | Path to the CA certificate used to validate the upstream CMP server certificate.       |         |
| `client_cert_path`     | Path to the client certificate used to authenticate to the upstream CMP endpoint.      |         |
| `client_cert_key_path` | Path to the private key matching `client_cert_path`.                                   |         |

```hcl
UpstreamAuthority "cmp" {
    plugin_data {
        hostname = "cmp.example.org"
        ca_cert_path = "/path/to/ca-cert.pem"
        client_cert_path = "/path/to/client-cert.pem"
        client_cert_key_path = "/path/to/client-key.pem"
    }
}
```

## Notes

This plugin is intended to be implemented as a real CMP client in a future change. Until then, it is only suitable as a placeholder for integration work and must not be used in production.
