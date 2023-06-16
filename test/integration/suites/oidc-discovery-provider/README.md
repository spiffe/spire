# Fetch x509-SVID Suite

## Description

This suite validates the OIDC discovery provider component. It starts spire server, spire agent and oidc discovery provider.
In this suite, the oidc discovery provider is first configured to fetch the JWKS from spire server API, them from the spire agent
workload API. This suite only test OIDC discovery provider using unix domain socket, ACME and Serving Certs configurations are not tested.
