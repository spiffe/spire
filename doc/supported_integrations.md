# Supported Integrations

SPIRE Server and Agent integrate with various software and platforms. The
following sections detail the official project support stance for these
integrations. Usually this means that we actively test the integration with the
listed versions (though not always; sometimes we rely on support declarations
of client libraries used by the integrations). If an integration is not
represented, it does not mean that the integration is not supported but that
there is no official stance.

## Envoy

The SPIRE project officially tests integrations against the latest five minor
versions of Envoy, starting with v1.13 (the earliest build with the v3 API).

Envoy v2 API support is deprecated and as such we only actively test against
the last minor version that supports it (v1.16).

## Kubernetes

The SPIRE project currently supports Kubernetes 1.18 through 1.21. Later
versions may also work but are not explicitly exercised by integration tests.
