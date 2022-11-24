# Roadmap

## Recently completed

* Use SPIRE on workloads [running on platforms where installing an agent is not possible](https://github.com/spiffe/spire/projects/9) (New!)
* Provide an [API](https://github.com/spiffe/spire-api-sdk/blob/main/proto/spire/api/server/trustdomain/v1/trustdomain.proto) on SPIRE Server to allow programmatic configuration of federation relationships (New!)
* [API](https://github.com/spiffe/spire-api-sdk) and [Plugin](https://github.com/spiffe/spire-plugin-sdk) SDKs for Integration authors
* Expand [support of TPM node attestation](https://github.com/spiffe/spire/pull/2111) to provide first-class verification and identification of TPM metadata (New!)
* Support for using [Cert-Manager as an upstream authority](https://github.com/spiffe/spire/pull/2274) to SPIRE (New!)
* AWS Support: Support for using [AWS KMS to store signing keys](https://github.com/spiffe/spire/pull/2066), [Support for internet-restricted environments](https://github.com/spiffe/spire/pull/2119)
* Support for using [GCP Certificate Authority Service as an upstream authority](https://github.com/spiffe/spire/pull/2172)

## Near-Term and Medium-Term

* Provide a turn-key Kubernetes experience that adheres to security best practices  (In Progress)
* Provide a privileged API on SPIRE Agent to delegate SVID management to platform integrators (In Progress)
* Support for supply chain provenance attestation by verification of binary signing (e.g. TUF/notary/in-toto metadata validation)
* Secretless authentication to Google Compute Platform by expanding OIDC Federation integration support

## Long-Term

* Key Revocation and Forced Rotation
* Ensure error messages are indicative of a direction towards resolution
* Improve health-check subsystem
* Secretless authentication to Microsoft Azure by expanding OIDC Federation integration support

***

## Credits

Thank you to [@anjaltelang](https://github.com/anjaltelang) for helping the SPIRE team keep this roadmap accurate and up-to-date 🎉
