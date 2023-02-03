# Roadmap

## Recently completed

* [Support for using Google Cloud Key Management Service to create, maintain, and rotate server key pairs](#3410)
* [Ability to have separate X.509-SVID and JWT-SVID TTLs, which can be configured both at the entry-level and server default level](#3445)
* [Experimental support for limiting the number of SVIDs in the agent's cache](#3181)
* [Experimental Windows support](https://github.com/spiffe/spire/projects/12)

## Near-Term and Medium-Term

* Key Revocation and Forced Rotation (In Progress)
* Provide a turn-key Kubernetes experience that adheres to security best practices  (In Progress)
* Deprecate the Notifier plugin interface in favor of a BundlePublisher interface, implementing plugins that push bundles to remote locations (In Progress)
* Support for supply chain provenance attestation by verification of binary signing (e.g. TUF/notary/in-toto metadata validation)
* Secretless authentication to Google Compute Platform by expanding OIDC Federation integration support

## Long-Term

* Re-evaluate SPIRE Server API authorization
* Ensure error messages are indicative of a direction towards resolution
* Secretless authentication to Microsoft Azure by expanding OIDC Federation integration support

***

## Credits

Thank you to [@anjaltelang](https://github.com/anjaltelang) for helping the SPIRE team keep this roadmap accurate and up-to-date 🎉
