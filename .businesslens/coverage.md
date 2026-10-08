---
scope: "SPIRE Server, SPIRE Agent, their command lines, their HTTP health checks, and the OIDC Discovery Provider."
method: Static inspection of source and documentation; no code was run.
covered:
  - description: "Server command line for entries, agents, tokens, bundles, federation, authorities, minting, health, debug, logger and validation."
    paths:
      - cmd/spire-server/cli/entry/
      - cmd/spire-server/cli/agent/
      - cmd/spire-server/cli/token/
      - cmd/spire-server/cli/bundle/
      - cmd/spire-server/cli/federation/
      - cmd/spire-server/cli/localauthority/
      - cmd/spire-server/cli/upstreamauthority/
      - cmd/spire-server/cli/authoritycommon/
      - cmd/spire-server/cli/x509/
      - cmd/spire-server/cli/jwt/
      - cmd/spire-server/cli/healthcheck/
      - cmd/spire-server/cli/debug/
      - cmd/spire-server/cli/logger/
      - cmd/spire-server/cli/validate/
      - cmd/spire-server/cli/cli.go
  - description: "Agent command line for fetching, watching and validating identities, health, debug, logger and validation."
    paths:
      - cmd/spire-agent/cli/api/
      - cmd/spire-agent/cli/healthcheck/
      - cmd/spire-agent/cli/debug/
      - cmd/spire-agent/cli/logger/
      - cmd/spire-agent/cli/validate/
      - cmd/spire-agent/cli/cli.go
  - description: "Server API services, caller authorization policy and authorized-entry computation."
    paths:
      - pkg/server/api/agent/
      - pkg/server/api/bundle/
      - pkg/server/api/debug/
      - pkg/server/api/entry/
      - pkg/server/api/health/
      - pkg/server/api/limits/
      - pkg/server/api/localauthority/
      - pkg/server/api/logger/
      - pkg/server/api/middleware/
      - pkg/server/api/rpccontext/
      - pkg/server/api/svid/
      - pkg/server/api/trustdomain/
      - pkg/server/api/agent.go
      - pkg/server/api/api.go
      - pkg/server/api/bundle.go
      - pkg/server/api/entry.go
      - pkg/server/api/id.go
      - pkg/server/api/ratelimit.go
      - pkg/server/api/selector.go
      - pkg/server/api/trustdomain.go
      - pkg/server/authpolicy/policy_data.json
      - pkg/server/authpolicy/policy.rego
      - pkg/server/authpolicy/defaults.go
      - pkg/server/authorizedentries/
      - pkg/server/endpoints/
  - description: "Server authority rotation, credential lifetimes, entry and agent pruning, and federated bundle refresh."
    paths:
      - pkg/server/ca/
      - pkg/server/credtemplate/
      - pkg/server/registration/
      - pkg/server/node/
      - pkg/server/bundle/client/
  - description: "Server datastore rules for entries, agents, bundles and federation relationships."
    paths:
      - pkg/server/datastore/sqlstore/sqlstore.go
  - description: "Agent Workload API, Envoy SDS and their middleware."
    paths:
      - pkg/agent/endpoints/
  - description: "Agent Admin API: Delegated Identity, debug and logger services."
    paths:
      - pkg/agent/api/
  - description: Agent SPIFFE Broker API.
    paths:
      - pkg/agent/broker/
  - description: "Agent node attestation, SVID rotation, entry sync and SVID cache."
    paths:
      - pkg/agent/attestor/
      - pkg/agent/svid/rotator.go
      - pkg/agent/manager/
      - pkg/agent/client/
      - pkg/agent/common/hintsfilter/
  - description: Trust-on-first-use check shared by node attestors.
    paths:
      - pkg/server/plugin/nodeattestor/base/
  - description: Shared HTTP health check listener.
    paths:
      - pkg/common/health/
  - description: OIDC Discovery Provider service.
    paths:
      - support/oidc-discovery-provider/
exclusions:
  - description: "Build, release, packaging and repository automation."
    paths:
      - .github/
      - release/
      - script/
      - Makefile
      - Dockerfile
      - Dockerfile.dev
      - Dockerfile.windows
  - description: Unit and integration test suites and fixtures.
    paths:
      - test/
  - description: "Shared logging, telemetry, profiling and audit logging libraries."
    paths:
      - pkg/common/telemetry/
      - pkg/common/log/
      - pkg/common/profiling/
      - pkg/server/api/audit/
  - description: Private protocol definitions and generated code.
    paths:
      - proto/
unmapped:
  - description: "Server and agent run commands: process startup, configuration loading and reload, and the agent's rebootstrap."
    paths:
      - cmd/spire-server/cli/run/
      - cmd/spire-agent/cli/run/
      - pkg/server/server.go
      - pkg/agent/agent.go
  - description: "WIT-SVID minting, fetching and authorities behind the wit-svid feature flag."
    paths:
      - cmd/spire-server/cli/wit/
      - cmd/spire-agent/cli/api/fetch_wit.go
  - description: Agent SVIDStore service that writes the SVIDs of store-SVID entries to external secret stores.
    paths:
      - pkg/agent/svid/store/
      - pkg/agent/manager/storecache/
      - pkg/agent/plugin/svidstore/
  - description: Server bundle publishers and notifiers that push the bundle to external stores.
    paths:
      - pkg/server/bundle/pubmanager/
      - pkg/server/plugin/bundlepublisher/
      - pkg/server/plugin/notifier/
  - description: "Node and workload attestor, key manager, upstream authority, credential composer and datastore plugins."
    paths:
      - pkg/server/plugin/
      - pkg/agent/plugin/
      - pkg/server/catalog/
      - pkg/agent/catalog/
      - pkg/common/catalog/
  - description: Authorization policy engine that loads custom OPA policies and data in place of the shipped policy.
    paths:
      - pkg/server/authpolicy/policy.go
      - pkg/server/authpolicy/validate.go
limitations: []
---

# Coverage
