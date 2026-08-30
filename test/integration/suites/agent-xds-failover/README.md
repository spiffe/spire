# Agent xDS server resolution and failover

This suite exercises the experimental `use_xds` agent option
(see `doc/spire_agent.md`). It verifies that an agent
whose SPIRE server connection is resolved via xDS prefers a primary server and
transparently fails over to a secondary when the primary is unavailable.

## Topology

- `postgres` — a single shared datastore used by both servers, so registration
  entries and the aggregated trust bundle (both servers' JWT signing keys) are
  shared.
- `spire-server-1`, `spire-server-2` — two SPIRE servers with identical config
  (apart from hostname), both using the shared datastore and a shared disk
  upstream root CA, so their SVIDs chain to the same root and either can serve
  the agent.
- `xds-control-plane` — a minimal `go-control-plane` management server (built
  from `xds/main.go`) serving a static ADS snapshot that places server-1 at EDS
  priority 0 and server-2 at priority 1. gRPC's priority load balancing prefers
  priority 0 and fails over to priority 1 when priority 0 is in
  TRANSIENT_FAILURE (i.e. server-1 is down).
- `spire-agent` — configured with `use_xds = true` and
  `server_address = "spire-server"` (the xDS listener name). Its xDS bootstrap
  (`conf/agent/xds-bootstrap.json`, referenced by `GRPC_XDS_BOOTSTRAP`) points
  at the control plane over an insecure channel and carries the node locality.

## How failover is verified

Each check fetches a JWT-SVID with a **unique audience**, which forces a
JWT-SVID cache miss and therefore a live `NewJWTSVID` RPC to whichever server
the xDS load balancer currently points at. The JWT header's `kid` identifies the
signing key, which is unique per server, so it reveals which server issued the
token:

1. Both servers up → issued by server-1 (preferred / priority 0).
2. server-1 stopped → issued by server-2 (failover / priority 1).
3. server-1 restarted, server-2 stopped → issued by server-1 (failback).
4. Both stopped → fetch fails (proves a live server was required, not the cache).

The suite asserts the "both up" kid equals the primary's kid and that the
failover kid differs, confirming both the preference and a genuine switch.
