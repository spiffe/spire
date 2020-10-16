# Envoy SDS Suite

## Description

Exercises [Envoy](https://www.envoyproxy.io/)
[SDS](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret)
compatability within SPIRE by wiring up two workloads that achieve connectivity
using Envoy backed with identities and trust information retrieved from the
SPIRE agent SDS implementation.

A customer container image is used that runs both Envoy and the SPIRE agent. Socat containers are used as the workload.

The test ensures both TLS and mTLS connectivity between the workload.
