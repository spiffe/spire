# Copilot instructions for SPIRE

SPIRE is the reference implementation of the SPIFFE APIs. It issues SPIFFE
identities (SVIDs) to workloads in the SVID formats defined by the SPIFFE
specifications. The codebase is Go and is organized around two long-running
processes, the SPIRE Server and the SPIRE Agent, plus a plugin system.

When reviewing or generating code, weigh the concerns covered below. All of
them matter, and more than one often applies to the same change: compatibility
guarantees, SPIFFE spec conformance, security and usability, and project
conventions.

## Review checklist

These questions come from the SPIRE maintainer review guidelines in
`MAINTAINERS.md` and are advisory prompts to surface issues, not a rigid gate:

- Is the use case the change addresses clearly understood?
- Does the change break any current user's expectations of behavior (a
  regression)?
- Can the change be misconfigured, and if so what is the impact?
- Does the change adhere to the SPIRE compatibility guarantee (see the
  Compatibility guarantees section below)?
- What are the failure modes? Can SPIRE keep running?
- If something goes wrong, will it be clear to the operator what happened and
  how to fix it?
- If the change introduces additional configurables, could some or all of them
  be replaced with a programmatic decision?

Changes to particularly sensitive areas, such as the agent's cache manager or
the server's CA, warrant extra scrutiny.

## Compatibility guarantees

SPIRE makes strong compatibility promises documented in `doc/upgrading.md`.
Treat a violation of these as a blocking issue.

- **Server-to-server version skew.** Servers in the same cluster must operate
  within +/- 1 minor version of each other. Do not introduce a change that
  breaks a server one minor version behind or ahead (for example a new field or
  RPC that an adjacent server cannot produce or understand).
- **Agent-to-server version skew.** Agents may be up to one minor version older
  than the oldest server and must never be newer than the oldest server. Do not
  add behavior that requires an agent and server to be the same version, or that
  breaks an agent one minor version behind.
- **Upgrade and downgrade paths.** Only single-minor-version jumps are
  supported, servers upgrade before agents, and SPIRE supports zero-downtime
  rolling upgrades when more than one server is present. Do not assume state
  written by a version more than one minor prior.
- **Built-in plugin config and behavior compatibility.** A backwards-incompatible
  change to a built-in plugin (config semantics, selectors produced, etc.) must
  log a deprecation warning and keep backwards compatibility for one minor
  version. Do not rename, retype, or remove a config key without a deprecation
  cycle.
- **Plugin interface compatibility.** A breaking change to a plugin interface
  must keep existing plugins working for one minor version cycle, with warnings.
- **Deprecation log markers.** Deprecation warnings must include the structured
  field `alert=true`. Configuration deprecations add `alert_type=deprecated_config`
  and deprecated plugin services add `alert_type=deprecated_service`.
- **Datastore/SQL changes.** Datastore schema changes must ship in at least one
  full minor release cycle before any code change depends on them.
- **Experimental features.** Features gated behind the `experimental` config
  section are exempt from the guarantees above. If a change touches a feature
  that was experimental, confirm the experimental marker is still accurate.

## SPIFFE specification conformance

SPIRE implements the SPIFFE specifications. The canonical, authoritative set of
specs lives at https://github.com/spiffe/spiffe/tree/main/standards. The set of
specifications and SVID profiles evolves over time, and new profiles are added,
so do not assume the specs are limited to the ones you already know from
training.

When a change touches spec-defined behavior (an SVID format, trust domain
parsing, the Workload API request/response shape, federation bundle format,
etc.), treat the specs in that repository as authoritative and verify
conformance against them rather than relying on prior knowledge, which may be
stale or incomplete. If you cannot consult the spec, raise spec-conformance
concerns as questions rather than asserting a defect. Likewise, flag
reinterpretations of ambiguous spec areas as questions for maintainers rather
than as defects.

## Security and usability

SPIRE is security-critical infrastructure. Watch for changes that could weaken
identity issuance, trust domain or bundle handling, SVID validation, key
management, or authentication and authorization between components. Consider
whether a change could be misconfigured, and what the impact of misconfiguration
would be. Vulnerabilities are reported privately to security@spiffe.io, not via
public issues or PRs.

SPIRE solves a complicated problem, so features, configurables, log and error
messages, documentation, and naming must stay accessible to people who are not
deeply familiar with SPIFFE or authentication systems. The maintainer guidelines
in `MAINTAINERS.md` set these expectations:

- **Secure by default, then "it just works".** Decisions should favor secure
  defaults first and ease of use second, in that order.
- **Minimize configurables.** Keep the number of configuration options as small
  as possible, especially when many users would need to set the option, or when
  its value (and its extremes) could significantly affect SPIRE performance,
  reliability, or security. Prefer a programmatic decision over a new
  configurable where one is feasible.
- **The beginner measure.** A beginner should be able to quickly understand a
  feature or configurable and its impacts, and should be able to troubleshoot
  and be clearly informed when something important goes wrong. Favor clear,
  actionable log and error messages over silent failure.

## Repository layout

- `cmd/{spire-server,spire-agent}/`: CLI implementations of the server and
  agent commands.
- `pkg/{agent,server}/`: main logic of the agent and server processes and their
  support packages.
- `pkg/common/`: functionality shared by agent, server, and plugins.
- `pkg/{agent,server}/plugin/<name>/`: built-in plugin implementations.
- `proto/spire/common/`: shared protobuf definitions (package `spire.common`),
  with plugin-related common types under `proto/spire/common/plugin/`.
- `proto/private/`: internal protobuf definitions that are not part of the
  public API, for example `proto/private/server/journal/`.

The public gRPC API and plugin interface protobufs live in separate
repositories (`spire-api-sdk` and `spire-plugin-sdk`, both dependencies in
`go.mod`), not in this repository.

Packages should be exported through interfaces, and interaction with a package
should go through its interface. Define an interface in its own lowercase file
named after the interface.

Platform-specific code is split across files guarded by build constraints, by
convention named `<name>_posix.go` and `<name>_windows.go`. A change to one
platform's file usually needs a corresponding change in its sibling so that
behavior and validation stay consistent across platforms.

## Go conventions

- Write idiomatic Go. Prefer standard library and existing helpers over manual
  plumbing, and match the patterns in sibling files (error wrapping, validation,
  output formatting).
- Errors start with a lower case letter. Neither error messages nor log
  messages end with a period.
- Log messages use structured logging fields to convey context rather than
  string formatting, which increases message cardinality and hinders
  aggregation. Log message text itself uses standard casing.

### Language version

This project targets a modern Go toolchain, and the toolchain is updated
periodically. Treat the `.go-version` file at the repository root as the single
source of truth for the language version: assume all language and standard
library features up to that version are available, and do not flag valid modern
Go as an error based on an assumed older version. Do not hardcode a version
assumption from this document. In particular, do not raise any of the following
(all valid in the toolchain this project uses):

- **Ranging over an integer.** `for range n` and `for i := range n` where `n`
  is an integer are valid since Go 1.22. Do not claim `range` cannot iterate
  over an `int` or that such code does not compile.
- **Per-iteration loop variables.** Since Go 1.22 each loop iteration gets a
  fresh copy of the loop variable. A goroutine or closure that captures a `for`
  loop variable does not observe later iterations' values, so do not flag the
  classic "loop variable captured by reference" race for plain `for range` or
  three-clause `for` loops. (Variables declared inside the loop body with `:=`
  were already per-iteration before 1.22.)
- **`min`, `max`, and `clear` builtins**, and other features introduced up to
  the toolchain's version.

If you believe a construct fails to compile, prefer assuming it is valid modern
Go rather than reporting a build error based on an older language version.

## Metrics

- Label names should be constants defined in the `telemetry` package, and
  metrics should be defined centrally in `telemetry` or its subpackages.
- Count in aggregate: accumulate counts in a loop and emit a single metric after
  the loop rather than emitting one metric per iteration.
- Labels must be singular: a label name appears at most once per metric, its
  value is never an array or slice, and a given label must appear on every
  instance of a metric rather than conditionally.
- Keep `doc/telemetry/telemetry.md` up to date when metrics change, and unit
  test metrics where reasonable.

## Testing

- Prefer fake implementations over generated mocks. Mocks encode specific call
  patterns and are brittle; fakes implement the assumed behavior of a dependency
  in one maintainable place.
- Use table-driven tests when there is more than one case, with a `name` field
  per case.
- Never use `time.Sleep` to synchronize tests. Use proper synchronization such
  as `require.Eventually`, channels, sync primitives, mock clocks, or explicit
  control like `os.Chtimes`.
- Include tests and regression coverage for behavior changes.
- Before flagging a data race or test flakiness caused by "parallel execution"
  (for example a package-level variable mutated by a test), confirm the affected
  tests actually run in parallel by calling `t.Parallel()`. Tests run serially
  within a package unless they opt in, and SPIRE intentionally uses package-level
  test hooks in some places, so do not assert a parallel-execution race without
  that evidence.

## Building, testing, and linting

A Makefile drives common tasks and installs the required toolchain as needed.

- `make build` builds the binaries; `make all` builds, lints, and runs the unit
  tests.
- `make test` runs the unit tests, and `make race-test` runs them with the race
  detector. Validate code changes with these before considering them done.
- `make lint` runs the linters: `lint-code` (golangci-lint, configured in
  `.golangci.yml`) and `lint-md` (markdown). Code and docs should pass lint.
- `make generate` regenerates the protobuf code (`.pb.go`) from `.proto` files
  using the pinned `spire-plugin-sdk` version, and `make generate-check` verifies
  the generated code is current. After changing a `.proto` file, run
  `make generate` and commit the regenerated output.

## Contribution mechanics

- Every commit must be signed off with a DCO (`git commit -s`).
- Substantial changes should be tied to a triaged issue.
- Update documentation when behavior or configuration changes. Check whether a
  relevant file under `doc/` needs to be updated (for example a plugin's
  reference doc).
- When a change adds, removes, or modifies a configuration setting, update the
  full reference config files as well: `conf/agent/agent_full.conf` for agent
  settings and `conf/server/server_full.conf` for server settings.
