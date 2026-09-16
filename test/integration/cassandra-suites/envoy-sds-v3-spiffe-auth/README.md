# Envoy SDS v3 SPIFFE Auth Suite

## Description

Exercises [Envoy](https://www.envoyproxy.io/)
[SDS](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret)
compatibility within SPIRE by wiring up two workloads that achieve connectivity
using Envoy backed with identities and trust information retrieved from the
SPIRE agent SDS implementation. Using [SPIFFE Validator](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls_spiffe_validator_config.proto)
for certificates handshake.

A customer container image is used that runs both Envoy and the SPIRE Agent. Socat containers are used as the workload.

The test ensures both TLS and mTLS connectivity between the workload. This is exercised with a federated workload and also with a not federated workload.

                           upstream-spire-server                             downtream-federated-spire-server
                           /                    \                                            |
                          /                      \                                           |
             downtream-proxy                   upstream-proxy                   downstream-federated-proxy
             /             \                        |                           /                       \
            |               |                       |                          |                         |
    downtream-socat-mtls  downstream-socat-tls  upstream-socat     downstream-federated-socat-mtls  downstream-federated-socat-tls 
