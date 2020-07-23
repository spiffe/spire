![SPIRE Logo](/doc/images/spire_logo.png)

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3303/badge)](https://bestpractices.coreinfrastructure.org/projects/3303)
[![Build Status](https://travis-ci.org/spiffe/spire.svg?branch=master)](https://travis-ci.org/spiffe/spire)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/spire/badge.svg?branch=master)](https://coveralls.io/github/spiffe/spire?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/spiffe/spire)](https://goreportcard.com/report/github.com/spiffe/spire)
[![Slack Status](https://slack.spiffe.io/badge.svg)](https://slack.spiffe.io)

SPIRE (the [SPIFFE](https://github.com/spiffe/spiffe) Runtime Environment) is a toolchain of APIs for establishing trust between software systems across a wide variety of hosting platforms. SPIRE exposes the [SPIFFE Workload API](https://github.com/spiffe/go-spiffe/blob/master/proto/spiffe/workload/workload.proto), which can attest running software systems and issue [SPIFFE IDs](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md) and [SVID](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md)s to them.  This in turn allows two workloads to establish trust between each other, for example by establishing an mTLS connection or by signing and verifying a JWT token. SPIRE can also enable workloads to securely authenticate to a secret store, a database, or a cloud provider service.


- [Get SPIRE](#get-spire)
- [Learn about SPIRE](#learn-about-spire)
- [Integrate with SPIRE](#integrate-about-spire)
- [Contribute to SPIRE](#contribute-to-spire)
- [Further Reading](#further-reading)
- [Security](#security)



SPIRE was adopted by the [Cloud Native Computing Foundation](https://cncf.io) (CNCF) as a [sandbox-level project in 2018](https://www.cncf.io/blog/2018/03/29/cncf-to-host-the-spiffe-project/). If you are an organization that wants to help shape the evolution of technologies that are container-packaged, dynamically-scheduled and microservices-oriented, consider joining the CNCF.

## Get SPIRE

- Pre-built releases of SPIRE can be found at [https://github.com/spiffe/spire/releases](https://github.com/spiffe/spire/releases). These releases contain both SPIRE Server and SPIRE Agent binaries.
- Alternatively, you can [build SPIRE from source](/CONTRIBUTING.md).

## Learn about SPIRE

- Before trying SPIRE, it's a good idea to learn about its [architecture](https://spiffe.io/spire/) and design goals.
- Once ready to get started, see the [Quickstart Guides](https://spiffe.io/spire/try/) for Kubernetes, Linux, and MacOS.
- There are several examples demonstrating SPIRE usage in the [spire-examples](https://github.com/spiffe/spire-examples) repository.
- Check [ADOPTERS.md](./ADOPTERS.md) for a list of production SPIRE adopters, a view of the ecosystem, and use cases.
- See the [SPIRE Roadmap](https://github.com/spiffe/spire/wiki/Roadmap) for a list of planned features and enhancements.
- [Join](https://slack.spiffe.io/) the SPIFFE community on Slack. If you have any questions about how SPIRE works, or how to get it up and running, the best places to ask questions are the [SPIFFE Slack channels](https://spiffe.slack.com).

## Integrate with SPIRE

- See [Extend SPIRE](https://spiffe.io/spire/docs/extending/) to learn about the highly extensible SPIRE plugin framework.
- Client libraries for interacting with the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Workload_API.md) are available in [Go](https://github.com/spiffe/go-spiffe/tree/master/v2), [Java](https://github.com/spiffe/java-spiffe/tree/v2-api) and [C++](https://github.com/spiffe/c-spiffe) languages. See [SPIFFE Library Usage Examples](https://spiffe.io/spire/try/spiffe-library-usage-examples/) for code samples.
- SPIRE provides an implementation of the [Envoy](https://envoyproxy.io) [Secret Discovery Service](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret) (SDS) for use with [Envoy Proxy](https://envoyproxy.io).  SDS can be used to transparently install and rotate TLS certificates and trust bundles in Envoy. See [Using SPIRE with Envoy](https://spiffe.io/spire/docs/envoy/) for more information.

## Contribute to SPIRE

The SPIFFE community maintains the SPIRE project. Information on the various SIGs and relevant standards can be found in
https://github.com/spiffe/spiffe.

- See [CONTRIBUTING](https://github.com/spiffe/spire/blob/master/CONTRIBUTING.md) to get started.
- Use [GitHub Issues](https://github.com/spiffe/spire/issues) to request features or file bugs.
- See [GOVERNANCE](https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md) for SPIFFE and SPIRE governance policies.

## Further Reading

- The [Scaling SPIRE guide](/doc/scaling_spire.md) covers design guidelines, recommendations, and deployment models.
- For an explanation of how SPIRE compares to related systems such as secret stores, identity providers, authorization policy engines and service meshes see [comparisons](https://spiffe.io/spire/comparisons/).

## Security

### Security Assessments

The [CNCF Special Interest Group for Security]([https://github.com/cncf/sig-security](https://github.com/cncf/sig-security)) has conducted two assessments on SPIFFE and SPIRE design and configuration with respect to security.  The following documents contain summary reports as well as the threat modeling material produced as part of the assessment:

- [Scrutinizing SPIRE to Sensibly Strengthen SPIFFE Security](https://blog.scytale.io/scrutinizing-spire-security-9c82ba542019)
- [SIG-Security SPIFFE/SPIRE Security Assessment: summary](https://github.com/cncf/sig-security/tree/master/assessments/projects/spiffe-spire)
- [SIG-Security SPIFFE/SPIRE Security Assessment: full document](https://github.com/cncf/sig-security/blob/master/assessments/projects/spiffe-spire/self-assessment.md)

### Reporting Security Vulnerabilities

If you've found a vulnerability or a potential vulnerability in SPIRE please let us know at security@spiffe.io. We'll send a confirmation email to acknowledge your report, and we'll send an additional email when we've identified the issue positively or negatively.
