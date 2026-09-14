# Ghostunnel + Federation Suite

## Description

Exercises [Ghostunnel](https://github.com/square/ghostunnel) SPIFFE Workload
API by wiring up two workloads that achieve connectivity using Ghostunnel
backed with identities and trust information retrieved from the SPIFFE Workload
API.

The two workloads are in separate trust domains and are federated using the
SPIRE bundle endpoints. This enables each Ghostunnel proxy to authenticate
identities issued by the other trust domain.

A custom container image is used that runs Ghostunnel, SPIRE agent, and socat
(acting as the workload).

The SPIRE server and agent in each trust domain are brought down during different
portions of the test to ensure that as long as the SVID is valid, ghostunnel
connectivity is not disrupted by a little downtime.
