![SPIRE Logo](/doc/images/spire_logo.png)

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3303/badge)](https://bestpractices.coreinfrastructure.org/projects/3303)
[![Build Status](https://github.com/spiffe/spire/actions/workflows/pr_build.yaml/badge.svg)](https://github.com/spiffe/spire/actions/workflows/pr_build.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/spiffe/spire)](https://goreportcard.com/report/github.com/spiffe/spire)
[![Production Phase](https://img.shields.io/badge/SPIFFE-Prod-green.svg?logoWidth=18&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHJvbGU9ImltZyIgdmlld0JveD0iMC4xMSAxLjg2IDM1OC4yOCAzNTguMjgiPjxzdHlsZT5zdmcge2VuYWJsZS1iYWNrZ3JvdW5kOm5ldyAwIDAgMzYwIDM2MH08L3N0eWxlPjxzdHlsZT4uc3QyLC5zdDN7ZmlsbC1ydWxlOmV2ZW5vZGQ7Y2xpcC1ydWxlOmV2ZW5vZGQ7ZmlsbDojYmNkOTE4fS5zdDN7ZmlsbDojMDRiZGQ5fTwvc3R5bGU+PGcgaWQ9IkxPR08iPjxwYXRoIGQ9Ik0xMi4xIDguOWgyOC4zYzIuNyAwIDUgMi4yIDUgNXYyOC4zYzAgMi43LTIuMiA1LTUgNUgxMi4xYy0yLjcgMC01LTIuMi01LTVWMTMuOWMuMS0yLjcgMi4zLTUgNS01eiIgY2xhc3M9InN0MiIvPjxwYXRoIGQ9Ik04OC43IDguOWgyNThjMi43IDAgNSAyLjIgNSA1djI4LjNjMCAyLjctMi4yIDUtNSA1aC0yNThjLTIuNyAwLTUtMi4yLTUtNVYxMy45YzAtMi43IDIuMi01IDUtNXoiIGNsYXNzPSJzdDMiLz48cGF0aCBkPSJNMzQ2LjcgODUuNWgtMjguM2MtMi43IDAtNSAyLjItNSA1djI4LjNjMCAyLjggMi4yIDUgNSA1aDI4LjNjMi43IDAgNS0yLjIgNS01VjkwLjVjMC0yLjgtMi4zLTUtNS01eiIgY2xhc3M9InN0MiIvPjxwYXRoIGQ9Ik0xOTMuNiA4NS41SDEyLjFjLTIuNyAwLTUgMi4zLTUgNXYyOC4zYzAgMi43IDIuMiA1IDUgNWgxODEuNWMyLjcgMCA1LTIuMiA1LTVWOTAuNWMwLTIuOC0yLjItNS01LTV6IiBjbGFzcz0ic3QzIi8+PHBhdGggZD0iTTI3MC4yIDg1LjVoLTI4LjNjLTIuNyAwLTUgMi4yLTUgNXYyOC4zYzAgMi44IDIuMiA1IDUgNWgyOC4zYzIuNyAwIDUtMi4yIDUtNVY5MC41Yy0uMS0yLjgtMi4zLTUtNS01eiIgY2xhc3M9InN0MiIvPjxwYXRoIGQ9Ik0yNzAuMiAxNjJIODguN2MtMi43IDAtNSAyLjItNSA1djI4LjNjMCAyLjcgMi4yIDUgNSA1aDE4MS41YzIuNyAwIDUtMi4yIDUtNVYxNjdjLS4xLTIuOC0yLjMtNS01LTV6IiBjbGFzcz0ic3QzIi8+PHBhdGggZD0iTTM0Ni43IDE2MmgtMjguM2MtMi43IDAtNSAyLjItNSA1djI4LjNjMCAyLjggMi4yIDUgNSA1aDI4LjNjMi43IDAgNS0yLjIgNS01VjE2N2MwLTIuOC0yLjMtNS01LTV6bS0zMDYuMyAwSDEyLjFjLTIuNyAwLTUgMi4yLTUgNXYyOC4zYzAgMi44IDIuMiA1IDUgNWgyOC4zYzIuNyAwIDUtMi4yIDUtNVYxNjdjMC0yLjgtMi4yLTUtNS01em0tMjguMyA3Ni41aDI4LjNjMi43IDAgNSAyLjIgNSA1djI4LjNjMCAyLjctMi4yIDUtNSA1SDEyLjFjLTIuNyAwLTUtMi4yLTUtNXYtMjguM2MuMS0yLjcgMi4zLTUgNS01eiIgY2xhc3M9InN0MiIvPjxwYXRoIGQ9Ik0xNjUuMiAyMzguNWgxODEuNWMyLjcgMCA1IDIuMiA1IDV2MjguM2MwIDIuNy0yLjIgNS01IDVIMTY1LjJjLTIuNyAwLTUtMi4yLTUtNXYtMjguM2MwLTIuNyAyLjItNSA1LTV6IiBjbGFzcz0ic3QzIi8+PHBhdGggZD0iTTg4LjcgMjM4LjVIMTE3YzIuNyAwIDUgMi4yIDUgNXYyOC4zYzAgMi43LTIuMiA1LTUgNUg4OC43Yy0yLjcgMC01LTIuMi01LTV2LTI4LjNjMC0yLjcgMi4yLTUgNS01em0yNTggNzYuN2gtMjguM2MtMi43IDAtNSAyLjItNSA1djI4LjNjMCAyLjggMi4yIDUgNSA1aDI4LjNjMi43IDAgNS0yLjIgNS01di0yOC4zYzAtMi44LTIuMy01LTUtNXoiIGNsYXNzPSJzdDIiLz48cGF0aCBkPSJNMjcwLjIgMzE1LjJoLTI1OGMtMi43IDAtNSAyLjItNSA1djI4LjNjMCAyLjcgMi4yIDUgNSA1aDI1OGMyLjcgMCA1LTIuMiA1LTV2LTI4LjNjLS4xLTIuOC0yLjMtNS01LTV6IiBjbGFzcz0ic3QzIi8+PC9nPjwvc3ZnPg==)](https://github.com/spiffe/spiffe/blob/main/MATURITY.md#production)

SPIRE (the [SPIFFE](https://github.com/spiffe/spiffe) Runtime Environment) is a toolchain of APIs for establishing trust between software systems across a wide variety of hosting platforms. SPIRE exposes the [SPIFFE Workload API](https://github.com/spiffe/go-spiffe/blob/main/v2/proto/spiffe/workload/workload.proto), which can attest running software systems and issue [SPIFFE IDs](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) and [SVID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)s to them.  This in turn allows two workloads to establish trust between each other, for example by establishing an mTLS connection or by signing and verifying a JWT token. SPIRE can also enable workloads to securely authenticate to a secret store, a database, or a cloud provider service.

- [Get SPIRE](#get-spire)
- [Learn about SPIRE](#learn-about-spire)
- [Integrate with SPIRE](#integrate-with-spire)
- [Contribute to SPIRE](#contribute-to-spire)
- [Further Reading](#further-reading)
- [Security](#security)

SPIRE is a [graduated](https://www.cncf.io/projects/spire/) project of the [Cloud Native Computing Foundation](https://cncf.io) (CNCF). If you are an organization that wants to help shape the evolution of technologies that are container-packaged, dynamically-scheduled and microservices-oriented, consider joining the CNCF.

## Get SPIRE

- Pre-built releases of SPIRE can be found at [https://github.com/spiffe/spire/releases](https://github.com/spiffe/spire/releases). These releases contain both SPIRE Server and SPIRE Agent binaries.
- Container images are published for [spire-server](https://ghcr.io/spiffe/spire-server), [spire-agent](https://ghcr.io/spiffe/spire-agent), and [oidc-discovery-provider](https://ghcr.io/spiffe/oidc-discovery-provider).
- Alternatively, you can [build SPIRE from source](/CONTRIBUTING.md).

## Learn about SPIRE

- Before trying SPIRE, it's a good idea to learn about its [architecture](https://spiffe.io/spire/) and design goals.
- Once ready to get started, see the [Quickstart Guides](https://spiffe.io/spire/try/) for Kubernetes, Linux, and MacOS.
- There are several examples demonstrating SPIRE usage in the [spire-examples](https://github.com/spiffe/spire-examples) and [spire-tutorials](https://github.com/spiffe/spire-tutorials) repositories.
- Check [ADOPTERS.md](./ADOPTERS.md) for a list of production SPIRE adopters, a view of the ecosystem, and use cases.
- See the [SPIRE Roadmap](/ROADMAP.md) for a list of planned features and enhancements.
- [Join](https://slack.spiffe.io/) the SPIFFE community on Slack. If you have any questions about how SPIRE works, or how to get it up and running, the best places to ask questions are the [SPIFFE Slack channels](https://spiffe.slack.com).
- Download the free book about SPIFFE and SPIRE, "[Solving the Bottom Turtle](https://spiffe.io/book/)."

## Integrate with SPIRE

- See [Extend SPIRE](https://spiffe.io/spire/docs/extending/) to learn about the highly extensible SPIRE plugin framework.
- Officially maintained client libraries for interacting with the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) are available in [Go](https://github.com/spiffe/go-spiffe/tree/main/v2) and [Java](https://github.com/spiffe/java-spiffe). See [SPIFFE Library Usage Examples](https://spiffe.io/spire/try/spiffe-library-usage-examples/) for a full list of official and community libraries, as well as code samples.
- SPIRE provides an implementation of the [Envoy](https://envoyproxy.io) [Secret Discovery Service](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret) (SDS) for use with [Envoy Proxy](https://envoyproxy.io).  SDS can be used to transparently install and rotate TLS certificates and trust bundles in Envoy. See [Using SPIRE with Envoy](https://spiffe.io/spire/docs/envoy/) for more information.

For supported integration versions, see [Supported Integrations](/doc/supported_integrations.md).

## Contribute to SPIRE

The SPIFFE community maintains the SPIRE project. Information on the various SIGs and relevant standards can be found in
<https://github.com/spiffe/spiffe>.

- See [CONTRIBUTING](https://github.com/spiffe/spire/blob/main/CONTRIBUTING.md) to get started.
- Use [GitHub Issues](https://github.com/spiffe/spire/issues) to request features or file bugs.
- See [GOVERNANCE](https://github.com/spiffe/spiffe/blob/main/GOVERNANCE.md) for SPIFFE and SPIRE governance policies.

## Further Reading

- The [Scaling SPIRE guide](/doc/scaling_spire.md) covers design guidelines, recommendations, and deployment models.
- For an explanation of how SPIRE compares to related systems such as secret stores, identity providers, authorization policy engines and service meshes see [comparisons](https://spiffe.io/spire/comparisons/).

## Security

### Security Assessments

A third party security firm ([Cure53](https://cure53.de/)) completed a security audit of SPIFFE and SPIRE in February of 2021. Additionally, the [CNCF Technical Advisory Group for Security](https://github.com/cncf/tag-security) conducted two assessments on SPIFFE and SPIRE in 2018 and 2020. Please find the reports and supporting material, including the threat model exercise results, below.

- [Cure53 Security Audit Report](doc/cure53-report.pdf)
- [SIG-Security SPIFFE/SPIRE Security Assessment: summary](https://github.com/cncf/sig-security/tree/main/community/assessments/projects/spiffe-spire)
- [SIG-Security SPIFFE/SPIRE Security Assessment: full assessment](https://github.com/cncf/sig-security/blob/main/community/assessments/projects/spiffe-spire/self-assessment.md)
- [Scrutinizing SPIRE to Sensibly Strengthen SPIFFE Security](https://blog.spiffe.io/scrutinizing-spire-security-9c82ba542019)

### Reporting Security Vulnerabilities

If you've found a vulnerability or a potential vulnerability in SPIRE please let us know at <security@spiffe.io>. We'll send a confirmation email to acknowledge your report, and we'll send an additional email when we've identified the issue positively or negatively.

<!-- markdownlint-configure-file { "MD041": false } -->
