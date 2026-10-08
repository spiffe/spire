# Workload API

Fetching SVIDs and validating JWT-SVIDs through the SPIFFE Workload API, from
a workload or from the agent command line.

## Boundary

It does not own Envoy secret discovery, the Delegated Identity API nor the
SPIFFE Broker API.
