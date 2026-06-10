# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

SPIRE is the SPIFFE Runtime Environment: a server + agent toolchain that attests workloads and issues SPIFFE IDs / SVIDs (X.509 and JWT). It is a CNCF graduated project. This is `github.com/spiffe/spire` (here, an Indeed fork; default branch `main-indeed`).

## Build / test / lint

Everything goes through the `Makefile`, which pins and auto-installs its own toolchain (protoc, golangci-lint, Go) under `.build/`. Use the make targets rather than raw tools — notably, `make lint-code` runs golangci-lint via `go run .../golangci-lint@<pinned-version>`, so a system-installed `golangci-lint` of a different version (which fails against this repo's Go target) is irrelevant.

- `make build` — build all binaries (`bin/spire-server`, `bin/spire-agent`, `bin/oidc-discovery-provider`); `make bin/spire-server` for one.
- `make test` — full unit suite (`go test ./...`). `make race-test` for the `-race` variant. `COVERPROFILE=out.cov make test` for coverage.
- `make lint` — `lint-code` (golangci-lint, config in `.golangci.yml`) + `lint-md`.
- `make all` — build + lint + test.
- `make generate` — regenerate protobuf / plugin / service `.pb.go` from `.proto`; `make generate-check` verifies generated code is current (must run on a clean tree). Run after editing any `.proto`.
- `make govulncheck`, `make tidy` / `tidy-check`.

Running focused tests directly with `go test` is fine and faster than `make test`:
- Single package: `go test ./pkg/server/ca/manager/`
- Single test: `go test ./pkg/common/bundleutil/ -run TestDedupSigningKeysByKid`
- Datastore and several plugins use **testify suites**, so the top-level `Test*` is the suite entry and methods are addressed with `/`: e.g. `go test ./pkg/server/datastore/sqlstore/ -run 'TestPlugin/TestAppendBundle'`.

Datastore unit tests run against **sqlite3** by default. MySQL/Postgres dialects are exercised via the integration harness (`test/integration/`, `make integration`), not plain `go test`.

## Architecture

Two processes, mirrored layouts: `pkg/server/` (the trust-domain authority) and `pkg/agent/` (runs on each node, attests workloads, exposes the SPIFFE Workload API). CLI entrypoints are in `cmd/spire-server` and `cmd/spire-agent`; `support/oidc-discovery-provider` serves a JWKS/OIDC endpoint from the trust bundle.

**Plugin framework (central).** Almost all pluggable behavior is a gRPC plugin built on `github.com/spiffe/spire-plugin-sdk`. Plugin categories live under `pkg/{server,agent}/plugin/<category>/<impl>/` — server: `keymanager`, `nodeattestor`, `upstreamauthority`, `notifier`, `bundlepublisher`, `credentialcomposer`; agent: `keymanager`, `nodeattestor`, `workloadattestor`, `svidstore`. Each impl exposes a `BuiltIn()` (`catalog.MakeBuiltIn(...)`); built-ins are wired into the process by being listed in `pkg/{server,agent}/catalog/<category>.go`. Plugins can also run as external binaries over the same gRPC contract, so an implementation must never assume in-process calls. The category interface package (e.g. `pkg/server/plugin/keymanager`) is the neutral contract shared by the host (CA manager, etc.) and the impls — put cross-cutting constants there, not in an impl or in `pkg/server/ca`.

**Server CA + HA rotation.** `pkg/server/ca/manager` prepares/activates/rotates the X509 CA, JWT, and WIT signing keys; `journal.go` persists rotation state to the datastore's `CAJournal` record. Multiple servers in one trust domain share the datastore (HA): each server finds *its* journal by matching a KeyManager key's X.509 SubjectKeyID against `active_x509_authority_id`. Key material is obtained from the configured `keymanager` plugin by a deterministic logical key ID (`x509-CA-*`, `JWT-Signer-*`, `WIT-Signer-*`, built in `slot.go`); the bundle (`common.Bundle`) is keyed by the JWT `kid`.

**Datastore.** The `datastore` plugin interface (`pkg/server/datastore`) is implemented by `sqlstore` (GORM over sqlite/MySQL/Postgres). Schema lives in `models.go`; migrations are versioned. Per repo convention, **a datastore/schema change must ship a full minor release before any code depends on it** — add the column/migration first, wire up the dependent logic in a later release.

**Protobuf.** `.proto` under `proto/spire/` (public API/common types) and `proto/private/` (internal, e.g. the CA journal). Generated `*.pb.go` is checked in and produced by `make generate`; never hand-edit generated files.

## Conventions

- This is a Go module (`go 1.26.3`); run `make tidy` after dependency changes.
- `make generate` after any `.proto` edit, and keep the generated output committed.
- Follow the existing testify-suite style when extending datastore/plugin tests; plugins use in-package fakes (`client_fake.go`) rather than network calls.
- `pkg/common/` is the only place shared by server, agent, and plugins — keep agent/server-specific code out of it.

## The task: shared JWT signing keys (fix "too many JWKS keys", #4699 / PR #6537)

This branch (`too_many_jwks_keys`) lets multiple SPIRE servers in one trust domain **share JWT signing key material** so the JWKS endpoint stops accumulating one key per server. The feature is configured per KeyManager plugin via a `shared_keys { ... }` block. Read this whole section before touching the CA manager or any keymanager plugin.

### The core problem and goal

In HA, every server independently prepares/activates/rotates its own JWT signing key, so the trust bundle's `JwtSigningKeys` (served as JWKS) grows with the server count and rotation history. Goal: when servers share the same JWT key *material*, that key should appear **once** in the JWKS, and the feature must not break X509 CA issuance or HA journal rotation. Only **JWT** keys are shared; X509 CA and WIT keys stay per-server.

### Challenges and how they were solved

1. **Random `kid` → no dedup.** The JWT/WIT `kid` was random (old `newKeyID()` via `crypto/rand`), independent of the key. Two servers sharing one key emitted different `kid`s, so the same public key landed in the JWKS under N `kid`s. **Solution:** derive the `kid` deterministically from the public key — `deterministicKeyID(signer)` in `pkg/server/ca/manager/manager.go` calls `x509util.GetSubjectKeyID` + `SubjectKeyIDToString` (the same SKI derivation X509 authority IDs use). Now all servers compute the same `kid` for the same key. (`newJWTKey`/`newWITKey` use it; the old `newKeyID`/`keyIDFromBytes` were removed.)

2. **`NotAfter` divergence → deterministic `kid` alone still doesn't dedup.** The bundle is merged in `appendBundle` (`pkg/server/datastore/sqlstore/sqlstore.go`) via `bundleutil.MergeBundles`, which dedups by the *entire* `PublicKey.String()` — including `NotAfter`. Each server computes `NotAfter = now + caTTL` independently, so the same shared key still produced two entries with the *same* `kid` (which also tripped the "another key with the same KeyID" guards in `taintJWTKey`/`revokeJWTKey`). **Solution:** `bundleutil.DedupSigningKeysByKid(bundle)` collapses JWT/WIT entries sharing a `kid` to one, keeping the **max `NotAfter`** and OR-ing `TaintedKey`; called right after `MergeBundles` in `appendBundle`. It is a no-op when `kid`s are distinct, so non-shared deployments are unaffected. **Do not** change `MergeBundles` itself (it has other callers and intentionally compares full content).

3. **Restart key-ownership / journal collision.** A server finds *its* CA journal in `findCAJournal` (`pkg/server/ca/manager/journal.go`) by computing the X509 SubjectKeyID of each key `km.GetKeys()` returns and matching `active_x509_authority_id`. This assumes the key store is private to the server. Naively sharing *all* key types means `km.GetKeys()` returns other servers' X509 keys, so a restarting server can adopt a **foreign journal**. **Solution:** scope sharing to **JWT keys only**. X509 CA and WIT keys remain per-server (namespaced by a server identifier), so `km.GetKeys()` returns this server's unique X509 key + the shared JWT keys, the X509 match stays unique, and **`findCAJournal` needed no change**. A server identifier is therefore **required even when `shared_keys` is enabled**. The JWT-vs-other distinction is made by key-ID prefix via `keymanager.IsSharedKeyID(id)` (true iff prefix `JWT-Signer-`); the prefixes `X509CAKeyIDPrefix`/`JWTSignerKeyIDPrefix`/`WITSignerKeyIDPrefix` are exported from `pkg/server/plugin/keymanager/constant.go` and used by both `slot.go` and every plugin.

4. **Cross-server race when creating/rotating the shared key.** Two servers preparing the same shared JWT key at once must not both mint new material. **Solution (already present in the plugins, kept JWT-only):** a distributed lock plus an optimistic freshness check. On `GenerateKey` for a JWT key, the plugin (a) optimistically reuses an existing key if it was created within a **15-minute freshness window** (`sharedKeyFreshnessThreshold`) and the key type matches; otherwise (b) acquires a lock (a lock alias/label/tag whose value is a timestamp), re-checks freshness, creates the key, then releases the lock. Stale locks older than **`lockTTL` (10 min)** are broken. Per-server in-process races are separately serialized (e.g. disk takes a file lock; awskms holds `p.mu`). These lock/freshness paths are now gated on `IsSharedKeyID` so X509/WIT never take the shared path.

5. **Discovery on restart (which keys are mine).** With a shared store, a server must rediscover the shared JWT keys **and** its own per-server X509/WIT keys, without picking up other servers' per-server keys. **Solution:** each plugin's key discovery became composite — match shared JWT keys by the configured template/regex, and match per-server keys only when they carry this server's identity (server-id alias prefix / label / tag). See per-plugin notes.

### Per-plugin mechanics (`pkg/server/plugin/keymanager/<impl>/`)

All four share the policy "JWT shared, X509/WIT per-server, server identifier required when shared," but each KeyManager identifies and stores keys differently:

- **disk** (`disk/disk.go`) — single shared keys file on a shared volume. Trickiest. Added a per-server id (`key_identifier_file`/`key_identifier_value` → `getOrCreateServerID`) and a `server_id` field on each on-disk `keyEntryRecord`. JWT keys are stored under the `crypto_key_template`-derived slot (shared across servers); X509/WIT under a `<serverID>/<keyID>` slot. Load **filters** to this server's records + shared JWT records; writes use **raw read-modify-write** (`persistKey`/`loadKeyData`/`writeKeyData`) so a server never clobbers another server's records in the shared file. Reuse (`checkReuse`) applies the 15-min window only to JWT keys.
- **awskms** (`awskms/awskms.go`, `fetcher.go`) — KMS aliases. `generateAliasName` branches: JWT → `jwt_key_alias_template`; else → the per-server alias `alias/SPIRE_SERVER/<td>/<serverID>/<keyID>` (`aliasFromSpireKeyID`). `GenerateKey` routes non-JWT keys through the simple create-and-alias path; only JWT keys use the lock/freshness path. The fetcher's `keyIDExtractor` is composite: try the shared `key_id_extraction_regex`, else the per-server alias prefix.
- **gcpkms** (`gcpkms/gcpkms.go`, `fetcher.go`) — Cloud KMS, **label-filter** discovery. `generateCryptoKeyID` branches (JWT → `crypto_key_template`; else `spire-key-<serverID>-<keyID>`). A `useSharedKey := sharedKeysEnabled && IsSharedKeyID(id)` local gates every shared block in `createKey` (optimistic reuse, KID label, lock-label acquisition/release, freshness re-check). In shared mode the fetcher lists *all* active keys in the trust domain (broad label filter) and the composite extractor narrows per-server keys via the `spire-server-id` label.
- **azurekeyvault** (`azure_key_vault.go`, `fetcher.go`) — Key Vault, **tag** based. Same `useSharedKey` gating in `createKey` (incl. the rotation-deletion branch). `generateKeyName` branches (JWT → `jwt_key_template`; else `spire-key-<uuid>-<keyID>` — per-server names use a random UUID, and server identity lives in the `spire-server-id` tag, so the name parser is serverID-agnostic). Composite extractor: regex for JWT, else `spire-server-id` tag == this server.

### Key files / symbols

- `pkg/server/ca/manager/manager.go` — `deterministicKeyID`, `newJWTKey`/`newWITKey`.
- `pkg/server/ca/manager/slot.go` — `x509CAKmKeyID`/`jwtKeyKmKeyID`/`witKeyKmKeyID` (use the exported prefix constants).
- `pkg/server/ca/manager/journal.go` — `findCAJournal` (the per-server binding that JWT-only scoping protects).
- `pkg/common/bundleutil/bundle.go` — `DedupSigningKeysByKid` / `dedupPublicKeysByKid`; wired in `pkg/server/datastore/sqlstore/sqlstore.go` `appendBundle`.
- `pkg/server/plugin/keymanager/constant.go` — `IsSharedKeyID` and the key-ID prefix constants.
- Plugin docs: `doc/plugin_server_keymanager_{disk,aws_kms,gcp_kms,azure_key_vault}.md`.

### Status and what's left

Done and committed (4 commits, newest last: `c46739c9` core kid+dedup, then `awskms`, `gcpkms`, `azurekeyvault`). Each component has unit tests; per plugin see `Test...SharedKeys...` and the `*_OnlyJWTKeysAreShared` tests; disk also has a restart/dual-discovery test (`TestSharedKeyOnlyJWTKeysAreShared`).

**Out of scope (intended follow-ups, not yet done):**
- Populating/querying `active_jwt_authority_id` — the `CAJournal` model column exists (added upstream in #4465) but is **never written or read** by application code. Wiring it would give JWT keys first-class journal identity for cross-server coordination. Remember the datastore minor-release rule before depending on it.
- Cross-server **tainting / bundle-removal** coordination: a deterministic `kid` removes duplicate entries but does not decide *which* server may rotate/taint/remove a shared key. Reviewers (sorindumitru on PR #6537) flagged this as the remaining hard problem; it likely needs server-to-server signaling.

### Gotchas for the next agent

- **Deterministic-`kid` convergence is gradual.** On upgrade, `kid`s are loaded from the journal (`slot.go` `loadJWTKeySlotFromEntry`), so existing keys keep their old random `kid`; only newly-prepared keys get deterministic ones. The plugin docs already state existing keys can't be used after enabling shared mode (start fresh).
- **gcp/azure per-server name parsers assume a UUID-shaped server id** (`getSPIREKeyIDFromCryptoKeyName`, `spireKeyIDFromKeyName` use a fixed UUID-length offset). This is pre-existing; a generated `key_identifier_file` (UUID) is safe, a short custom `key_identifier_value` can mis-parse per-server names on rediscovery.
- **FIPS** mode changes the SKI hash (`pkg/common/x509util/keyid.go`: SHA-256-first-20 vs SHA-1), so the `kid` value differs by mode — servers sharing a key must run the same FIPS mode.
- **Test fakes** return *deterministic* key material (`test/testkey`), and azure's fake `CreateKey` stamps its own `serverID` ignoring passed tags — so the JWT-only tests assert on **storage layout / names / tags**, not key bytes.
- When adding a new exported symbol, no doc comment is required (`.golangci.yml` does not enable revive's `exported` rule), but match the surrounding style. Run `make lint-code` (not a system `golangci-lint`).
