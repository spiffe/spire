# Changelog

## [1.8.0] - 2023-09-20

### Added

- `azure_key_vault` KeyManager plugin (#4458)
- Server configuration to set refresh hint of local bundle (#4400)
- Support for batch entry deletion in `spire-server` CLI (#4371)
- `aws_iid` NodeAttestor can now be used in AWS Gov Cloud and China regions (#4427)
- `status_code` and `status_message` fields in SPIRE Agent logs on gRPC errors (#4262)

### Changed

- Bundle server configuration is now organized by endpoint profiles (#4476)
- Release artifacts are now statically linked with musl rather than glibc (#4491)
- Agent no longer requests unused SVIDs for node aliases they belong to, reducing server signing load (#4467)
- Entry IDs can now be optionally set by the client for BatchCreateEntry requests (#4477)

### Fixed

- Concurrent workload attestation using `systemd` plugin (#4360)
- Bug in `k8s` WorkloadAttestor plugin that failed attestation in some scenarios (#4468)
- Server can now be run on Linux arm64 when using SQLite (#4491)

### Removed

- Support for Envoy SDS v2 API (#4444)
- Server no longer cleans up stale data in the database on startup (#4443)
- Server no longer deletes entries with invalid SPIFFE IDs on startup (#4449)

## [1.7.2] - 2023-08-16

### Added

- `aws_s3` BundlePublisher plugin (#4355)
- SPIRE Server bundle endpoint now includes bundle sequence number (#4389)
- Telemetry in experimental Agent LRU cache (#4335)
- Telemetry in Agent Delegated Identity API (#4399)
- Documentation improvements (#4336, #4407)

### Fixed

- Server no longer unnecessarily activates its CA a second time on startup (#4368)

## [1.7.1] - 2023-07-27

### Added

- x509pop node attestor emits a new selector with the leaf certificate serial number (#4216)
- HTTPS server in the OIDC Discovery Provider can now be configured to use a certificate file (#4190)
- Option to log source information in server and agent logs (#4246)

### Changed

- Agent now has an exponential backoff strategy when syncing with the server (#4279)

### Fixed

- Regression causing X509 CAs minted by an UpstreamAuthority plugin to be rejected if they have the digitalSignature key usage set (#4352)
- SPIRE Agent cache bug resulting in workloads receiving JWT-SVIDs with incomplete audience set (#4309)
- The `spire-server agent show` command to properly show the "Can re-attest" attribute (#4288)

## [1.7.0] - 2023-06-14

### Added

- AWS IID Node Attestor now supports all regions, including GovCloud and regions in China (#4124)

### Fixed

- Systemd workload attestor fails with error `connection closed by user` (#4165)
- Reduced SPIRE Agent CPU usage during kubernetes workload attestation (#4240)

### Removed

- Envoy SDSv2 API is deprecated and now disabled by default (#4228)

## [1.6.5] - 2023-07-27

### Fixed

- Regression causing X509 CAs minted by an UpstreamAuthority plugin to be rejected if they have the digitalSignature key usage set (#4352)

## [1.6.4] - 2023-05-17

### Added

- ARM64 binaries are now included in the release artifacts (#4143)
- Various build script improvements (#4062, #4081, #4096, #4127)
- Various doc improvements (#4076)
- Workload API hint support (#3993, #4074)
- Improved performance when listing queries for PostgreSQL (#4111)
- Support for SPIFFE bundle sequence numbers (#4061)
- New Systemd Workload Attestor plugin (#4058)
- New [BundlePublisher](https://github.com/spiffe/spire-plugin-sdk/blob/v1.6.4/proto/spire/plugin/server/bundlepublisher/v1/bundlepublisher.proto) plugin type (#4022)
- New `agent purge` command for removing stale agent records (#3982)

### Fixed

- Bug determining if an entry was unique (#4063)

## [1.6.3] - 2023-04-12

### Added

- Entry API responses now include the `created_at` field (#3975)
- `spire-server agent` CLI commands and Agent APIs now show if agents can be re-attested and supports `by_can_reattest` filtering (#3880)
- Entry API along with `spire-server entry create`, `spire-server entry show` and `spire-server entry update` CLI commands now support hint information, allowing hinting to workloads the intended use of the SVID (#3926, #3787)

### Fixed

- The `vault` UpstreamAuthority plugin to properly set the URI SAN (#3971)
- Node selector data related to nodes is now cleaned when deleting a node (#3873)
- Clean stale node selector data from previously deleted nodes (#3941)
- Regression causing a failure to parse JSON formatted and verbose HCL configuration for plugins (#3939, #3999)
- Regression where some workloads with active FetchX509SVID streams were not notified when an entry is removed (#3923)
- The federated bundle updater now properly logs the trust domain name (#3927)
- Regression causing X509 CAs minted by an UpstreamAuthority plugin to be rejected if they did not have a URI SAN (#3997)

## [1.6.2] - 2023-04-04

### Security

- Updated to Go 1.20.3 to address CVE-2023-24534

## [1.6.1] - 2023-03-1

### Fixed

- Different CA TTL than configured (#3934)

## [1.6.0] - 2023-02-28

### Added

- Support for customization of SVID and CA attributes through CredentialComposer plugins (#3819, #3832, #3862, #3869)
- Experimental support to validate container images signatures through sigstore selectors (#3159)
- Published scratch images now support ARM64 architecture (#3607)
- Published scratch images are now signed using Sigstore (#3707)
- `spire-server mint` and `spire-server token generate` CLI commands now support the `-output` flag (#3800)
- `spire-agent api` CLI command now supports the `-output` flag (#3818)
- Release images now include a non-root user and default folders (#3811)
- Agent accepts bootstrap bundles in SPIFFE format (#3753)
- Database index for registration entry hint column (#3828)

### Changed

- Plugins are configured and executed in the order they are defined (#3797)
- Documentation improvements (#3826, #3842, #3870)

### Fixed

- Server crash when authorization layer was unable to talk to the datastore (#3829)
- Timestamps in logs are now consistently in local time (#3734)

### Removed

- Non-scratch images are no longer published (#3785)
- `k8s-workload-registar` is no longer released and maintained (#3853)
- Unused database column `x509_svid_ttl` from `registered_entries` table (#3808)
- The deprecated `enabled` flag from InMem telemetry config (#3796)
- The deprecated `default_svid_ttl` configurable (#3795)
- The deprecated `omit_x509svid_uid` configurable (#3794)

## [1.5.6] - 2023-04-04

### Added

- A log message in the k8s-workload-registrar webhook when validation fails (#4011)

### Security

- Updated to Go 1.19.8 to address CVE-2023-24534

## [1.5.5] - 2023-02-14

### Security

- Updated to Go 1.19.6 and golang.org/x/net v0.7.0 to address CVE-2022-41723, CVE-2022-41724, CVE-2022-41725.

## [1.5.4] - 2023-01-12

### Added

- Support to run SPIRE as a Windows service (#3625)
- Configure admin SPIFFE IDs from federated trust domains (#3642)
- New selectors in the `aws_iid` NodeAttestor plugin (#3640)
- Support for additional upstream root certificates to the `awssecret` UpstreamAuthority plugin (#3578)
- Serial number and revision number to SVID minting logging (#3699)
- `spire-server federation` CLI commands now support the `-output` flag (#3660)

### Fixed

- Service configurations provided by the gRPC resolver are now ignored by SPIRE Agent (#3712)
- CLI commands that supported the `-output` flag now properly shows the default value for the flag (#3713)

## [1.5.3] - 2022-12-14

### Added

- A new `gcp_kms` KeyManager plugin is now available (#3410, #3638, #3653, #3655)
- `spire-server agent`, `spire-server bundle`, and `spire-server entry` CLI commands now support `-output` flag (#3523, #3624, #3628)

### Changed

- SPIRE-managed files on Windows no longer inherit permissions from parent directory (#3577, #3604)
- Documentation improvements (#3534, #3546, #3461, #3565, #3630, #3632, #3639,)

### Fixed

- oidc-discovery-provider healthcheck HTTP server now binds to all network interfaces for visibility outside containers using virtual IP (#3580)
- k8s-workload-registrar CRD and reconcile modes now have correct example leader election RBAC YAML (#3617)

## [1.5.2] - 2022-12-06

### Security

- Updated to Go 1.19.4 to address CVE-2022-41717.

## [1.5.1] - 2022-11-08

### Fixed

- The deprecated `default_svid_ttl` configurable is now correctly observed after fixing a regression introduced in 1.5.0 (#3583)

## [1.5.0] - 2022-11-02

### Added

- X.509-SVID and JWT-SVID TTLs can now be configured separately at both the entry-level and Server default level (#3445)
- Entry protobuf type in `/v1/entry` API includes new `jwt_svid_ttl` field (#3445)
- `k8s-workload-registrar` and `oidc-discovery-provider` CLIs now print their version when the `-version` flag is set (#3475)
- Support for customizing SPIFFE ID paths of SPIRE Agents attested with the `azure_msi` NodeAttestor plugin (#3488)

### Changed

- Entry `ttl` protobuf field in `/v1/entry` API is renamed to `x509_ttl` (#3445)
- External plugins can no longer be named `join_token` to avoid conflicts with the builtin plugin (#3469)
- `spire-server run` command now supports DNS names for the configured bind address (#3421)
- Documentation improvements (#3468, #3472, #3473, #3474, #3515)

### Deprecated

- `k8s-workload-registrar` is deprecated in favor of [SPIRE Controller Manager](https://github.com/spiffe/spire-controller-manager) (#3526)
- Server `default_svid_ttl` configuration field is deprecated in favor of `default_x509_svid_ttl` and `default_jwt_svid_ttl` fields (#3445)
- `-ttl` flag in `spire-server entry create` and `spire-server entry update` commands is deprecated in favor of `-x509SVIDTTL` and `-jwtSVIDTTL` flags (#3445)
- `-format` flag in `spire-agent fetch jwt` CLI command is deprecated in favor of `-output` flag (#3528)
- `InMem` telemetry collector is deprecated and no longer enabled by default (#3492)

### Removed

- NodeResolver plugin type and `azure_msi` builtin NodeResolver plugin (#3470)

## [1.4.7] - 2023-02-14

### Security

- Updated to Go 1.19.6 and golang.org/x/net v0.7.0 to address CVE-2022-41723, CVE-2022-41724, CVE-2022-41725.

## [1.4.6] - 2022-12-06

### Security

- Updated to Go 1.19.4 to address CVE-2022-41717.

## [1.4.5] - 2022-11-01

### Security

- Updated to Go 1.19.3 to address CVE-2022-41716. This vulnerability only affects users configuring external Server or Agent plugins on Windows.

## [1.4.4] - 2022-10-05

### Added

- Experimental support for limiting the number of SVIDs in the agent's cache (#3181)
- Support for attesting Envoy proxy workloads when Istio is configured with holdApplicationUntilProxyStarts (#3460)

### Changed

- Improved bundle endpoint misconfiguration diagnostics (#3395)
- OIDC Discovery Provider endpoint now has a timeout to read request headers (#3435)
- Small documentation improvements (#3443)

## [1.4.3] - 2022-10-04

### Security

- Updated minimum TLS version to 1.2 for the k8s-workload-registrar CRD mode webhook and the oidc-discovery-provider when using ACME

## [1.4.2] - 2022-09-07

### Added

- The X509-SVID Subject field now contains a unique ID to satisfy RFC 5280 requirements (#3367)
- Agents now shut down when banned (#3308)

### Changed

- Small documentation improvements (#3309, #3377)

## [1.4.1] - 2022-09-06

### Security

- Updated to Go 1.18.6 to address CVE-2022-27664

## [1.4.0] - 2022-08-08

### Added

- Support for Windows workload attestation on Kubernetes (#3191)
- Support for using RSA keys with Workload X509-SVIDs (#3237)
- Support for anonymous authentication to the Kubelet secure port when performing workload attestation on Kubernetes (#3273)

### Deprecated

- The Node Resolver plugin type (#3272)

### Fixed

- Persistence of the can_reattest flag during agent SVID renewal (#3292)
- A regression in behavior preventing an agent from re-attesting when it has been evicted (#3269)

### Changed

- The Azure Node Attestor to optionally provide selectors (#3272)
- The Docker Workload Attestor now fails when configured with unknown options (#3243)
- Improved CRI-O support with Kubernetes workload attestation (#3242)
- Agent data stored on disk has been consolidated to a single JSON file (#3201)
- Agent and server data directories on Windows no longer inherit permissions from parent directory (#3227)
- Endpoints exposed using named pipes explicitly deny access to remote callers (#3236)
- Small documentation improvements (#3264)

### Removed

- The deprecated webhook mode from the k8s-workload-registrar (#3235)
- Support for the configmap leader election lock type from the k8s-workload-registrar (#3241)

## [1.3.6] - 2022-11-01

### Security

- Updated to Go 1.18.8 to address CVE-2022-41716. This vulnerability only affects users configuring external Server or Agent plugins on Windows.

## [1.3.5] - 2022-10-04

### Security

- Updated minimum TLS version to 1.2 for the k8s-workload-registrar CRD mode webhook and the oidc-discovery-provider when using ACME

## [1.3.4] - 2022-09-06

### Security

- Updated to Go 1.18.6 to address CVE-2022-27664

## [1.3.3] - 2022-07-13

### Security

- Updated to Go 1.18.4 to address CVE-2022-1705, CVE-2022-32148, CVE-2022-30631, CVE-2022-30633, CVE-2022-28131, CVE-2022-30635, CVE-2022-30632, CVE-2022-30630, and CVE-2022-1962.

## [1.3.2] - 2022-07-08

### Added

- Support for K8s workload attestation when the Kubelet is run as a standalone component (#3163)
- Optional health check endpoints to the OIDC Discovery Provider (#3151)
- Pagination support to the server `entry show` command (#3135)

### Fixed

- A regression in workload SVID minting that caused DNS names not to be set in the SVID (#3215)
- A regression in the server that caused a panic instead of a clean shutdown if a plugin was misconfigured (#3166)

### Changed

- Directories for UDS endpoints are no longer created by SPIRE on Windows (#3192)

## [1.3.1] - 2022-06-09

### Added

- The `windows` workload attestor gained a new `sha256` selector that can attest the SHA256 digest of the workload binary (#3100)

### Fixed

- Database rows related to registration entries are now properly removed (#3127, #3132)
- Agent reduces bandwidth use by requesting only required information when syncing with the server (#3123)
- Issue with read-modify-write operations when using PostgreSQL datastore in hot standby mode (#3103)

### Changed

- FetchX509Bundles RPC no longer sends spurious updates that contain no changes (#3102)
- Warn if the built-in `join_token` node attestor is attempted to be overridden by an external plugin (#3045)
- Database connections are now proactively closed when SPIRE server is shut down (#3047)

## [1.3.0] - 2022-05-12

### Added

- Experimental Windows support (<https://github.com/spiffe/spire/projects/12>)
- Ability to revert SPIFFE cert validation to standard X.509 validation in Envoy (#3009, #3014, #3020, #3034)
- Configurable leader election resource lock type for the K8s Workload Registrar (#3030)
- Ability to fetch JWT SVIDs and JWT Bundles on behalf of workloads via the Delegated Identity API (#2789)
- CanReattest flag to NodeAttestor responses to facilitate future features (#2646)

### Fixed

- Spurious message to STDOUT when there is no plugin_data section configured for a plugin (#2927)

### Changed

- SPIRE entries with malformed parent or SPIFFE IDs are removed on server startup (#2965)
- SPIRE no longer prepends slashes to paths passed to the API when missing (#2963)
- K8s Workload Registrar retries up to 5 seconds to connect to SPIRE Server (#2921)
- Improved error messaging when unauthorized resources are requested via SDS (#2916)
- Small documentation improvements (#2934, #2947, #3013)

### Deprecated

- The webhook mode for the K8s Workload Register has been deprecated (#2964)

## [1.2.5] - 2022-07-13

### Security

- Updated to Go 1.17.12 to address CVE-2022-1705, CVE-2022-32148, CVE-2022-30631, CVE-2022-30633, CVE-2022-28131, CVE-2022-30635, CVE-2022-30632, CVE-2022-30630, and CVE-2022-1962.

## [1.2.4] - 2022-05-12

### Added

- Ability to revert SPIFFE cert validation to standard X.509 validation in Envoy (#3009,#3014,#3020,#3034)

## [1.2.3] - 2022-04-12

### Security

- Updated to Go 1.17.9 to address CVE-2022-24675, CVE-2022-28327, CVE-2022-27536

## [1.2.2] - 2022-04-07

### Added

- SPIRE Server and Agent log files can be rotated by sending the `SIGUSR2` signal to the process (#2703)
- K8s Workload Registrar CRD mode now supports registering "downstream" workloads (#2885)
- SPIRE can now be compiled on macOS machines with an Apple Silicon CPU (#2876)
- Small documentation improvements (#2851)

### Changed

- SPIRE Server no longer sets the `DigitalSignature` KeyUsage bit in its CA certificate (#2896)

### Fixed

- The `k8sbundle` Notifier plugin in SPIRE Server no longer consumes excessive CPU cycles (#2857)

## [1.2.1] - 2022-03-16

### Added

- The SPIRE Agent `fetch jwt` CLI command now supports JSON output (#2650)

### Changed

- OIDC Discovery Provider now includes the `alg` parameter in JWKs to increase compatibility  (#2771)
- SPIRE Server now gracefully stops plugin servers, allowing outstanding RPCs a chance to complete (#2722)
- SPIRE Server logs additional authorization information with RPC requests (#2776)
- Small documentation improvements (#2746, #2792)

### Fixed

- SPIRE Server now properly rotates signing keys when prepared or activated keys are lost from the database (#2770)
- The AWS IID node attestor now works with instance profiles which have paths (#2825)
- Fixed a crash in SPIRE Agent caused by a race on the agent cache (#2699)

## [1.2.0] - 2022-01-28

### Added

- SPIRE Server can now be configured to mint agent SVIDs with a specific TTL (#2667)
- A set of fixed admin SPIFFE IDs can now be configured in SPIRE Server (#2677)

### Changed

- Upstream signed CA chain is now validated to prevent misconfigurations (#2644)
- Improved SVID signing logs to include more context (#2678)
- The deprecated agent key file (`svid.key`) is no longer proactively removed by the agent (#2671)
- Improved errors when agent path template execution fails due to missing key (#2683)
- SPIRE now consumes the SVIDStore V1 interface published in the SPIRE Plugin SDK (#2688)

### Deprecated

- API support for paths without leading slashes in `spire.api.types.SPIFFEID` messages has been deprecated (#2686, #2692)
- The SVIDStore V1 interface published in SPIRE repository has been renamed to `svidstore.V1Unofficial` and is now deprecated in favor of the interface published in the SPIRE Plugin SDK (#2688)

### Removed

- The deprecated `domain` configurable has been removed from the SPIRE OIDC Discovery Provider (#2672)
- The deprecated `allow_unsafe_ids` configurable has been removed from SPIRE Server (#2685)

## [1.1.5] - 2022-05-12

### Added

- Ability to revert SPIFFE cert validation to standard X.509 validation in Envoy (#3009,#3014,#3020,#3034)

## [1.1.4] - 2022-04-13

### Security

- Updated to Go 1.17.9 to address CVE-2022-24675, CVE-2022-28327, CVE-2022-27536

## [1.1.3] - 2022-01-07

### Security

- Fixed CVE-2021-44716

## [1.1.2] - 2021-12-15

### Added

- SPIRE Agent now supports the Delegated Identity API for delegating SVID management to trusted platform components (#2481)
- The K8s Workload Registrar now supports configuring DNS name templates (#2643)
- SPIRE Server now logs a message when expired registration entries are pruned (#2637)
- OIDC Discovery Provider now supports setting the `use` property on the JWKs it serves (#2634)

### Fixed

- SPIRE Agent now provides reason for failure during certain kinds of attestation errors (#2628)

## [1.1.1] - 2021-11-17

### Added

- SPIRE Agent can now store SVIDs with Google Cloud Secrets Manager (#2595)

### Changed

- SPIRE Server downloads federated bundles a little sooner when federated relationships are added or updated (#2585)

### Fixed

- Fixed a regression in Percona XTRA DB Cluster support introduced in 0.12.2 (#2605)
- Kubernetes Workload Attestation fixed for Kubernetes 1.21+ (#2600)
- SPIRE Agent now retries failed removals of SVIDs stored by SVIDStore plugins (#2620)

## [1.1.0] - 2021-10-10

### Added

- SPIRE images are now published to GitHub Container Registry. They will continue to be published to Google Container Registry over the course of the next release (#2576,#2580)
- SPIRE Server now implements the [TrustDomain API](https://github.com/spiffe/spire-api-sdk/blob/main/proto/spire/api/server/trustdomain/v1/trustdomain.proto) and related CLI commands (<https://github.com/spiffe/spire/projects/11>)
- The SVIDStore plugin type has been introduced to enable, amongst other things, agentless workload scenarios (#2176,#2483)
- The TPM DevID Node Attestor emits a new `issuer:cn` selector with the common name of the issuing certificate (#2581)
- The K8s Bundle Notifier plugin now supports pushing the bundle to resources in multiple clusters (#2531)
- A built-in AWS Secrets Manager SVIDStore plugin has been introduced, which can push workload SVIDs into AWS secrets for use in Lambda functions, etc. (#2542)
- The agent and entry list commands in the CLI gained additional filtering capabilities (#2478,#2479)
- The GCP CAS UpstreamAuthority has a new `ca_pool` configurable to identify which CA pool the signing CA resides in (#2569)

### Changed

- With the GA release of GCP CAS, the UpstreamAuthority plugin now needs to know which pool the CA belongs to. If not configured, it will do a pessimistic scan of all pools to locate the correct CA. This scan will be removed in a future release (#2569)
- The K8s Workload Registrar now supports Kubernetes 1.22 (#2515,#2540)
- Self-signed CA certificates serial numbers are now conformant to RFC 5280 (#2494)
- The AWS KMS Key Manager plugin now creates keys with a very strict policy by default (#2424)
- The deprecated agent key file (`svid.key`) is proactively removed by the agent. It was only maintained to accomodate rollback from v1.0 to v0.12 (#2493)

### Removed

- Support for the deprecated Registration API has been removed (#2487)
- Legacy (v0) plugin support has been removed. All plugins must now be authored using the plugin SDK.
- The deprecated `service_account_whitelist` configurables have been removed from the SAT and PSAT Node Attestor plugins (#2543)
- The deprecated `projectid_whitelist` configurable has been removed from the GCP IIT Node Attestor plugin (#2492)
- The deprecated `bundle_endpoint` and `registration_uds_path` configurables have been removed from SPIRE Server (#2486,#2519)

### Fixed

- The GCP CAS UpstreamAuthority now works with the GA release of GCP CAS (#2569)
- Fixed a variety of issues with the scratch image, preparatory to publishing as the official image on GitHub Container Registry (#2582)
- Kubernetes Workload Attestor now uses the canonical path for the service account token (#2583)
- The server socketPath is now appropriately overridden via the configuration file (#2570)
- The server now restarts appropriately after undergoing forceful shutdown (#2496)
- The server CLI list commands now work reliably for large listings (#2456)

## [1.0.4] - 2022-05-13

### Added

- Ability to revert SPIFFE cert validation to standard X.509 validation in Envoy (#3009,#3014,#3020,#3034)

## [1.0.3] - 2022-01-07

### Security

- Fixed CVE-2021-44716

## [1.0.2] - 2021-09-02

### Added

- Experimental support for custom authorization policies based on Open Policy Agent (OPA) (#2416)
- SPIRE Server can now be configured to emit audit logs (#2297, #2391, #2394, #2396, #2442, #2458)
- Envoy SDS v3 API in agent now supports the SPIFFE Certificate Validator for federated SPIFFE authentication (#2435, #2460)
- SPIRE OIDC Discovery Provider now intelligently handles host headers (#2404, #2453)
- SPIRE OIDC Discovery Provider can now serve over HTTP using the `allow_insecure_scheme` setting (#2404)
- Metrics configuration options to filter out metrics and labels (#2400)
- The `k8s-workload-registrar` now supports identity template based workload registration (#2417)
- Enhancements in filtering support in server APIs (#2467, #2463, #2464, #2468)
- Improvements in logging of errors in peertracker (#2469)

### Changed

- CRD mode of the `k8s-workload-registrar` now uses SPIRE certificates for the validating webhook (#2321)
- The `vault` UpstreamAuthority plugin now continues retrying to renew tokens on failures until the lease time is exceeded (#2445)

### Fixed

- Fixed a nil pointer dereference when the deprecated `allow_unsafe_ids` setting was configured (#2477)

### Deprecated

- The SPIRE OIDC Discovery Provider `domain` configurable has been deprecated in favor of `domains` (#2404)

## [1.0.1] - 2021-08-05

### Added

- LDevID-based TPM attestation can now be performed via a new `tpm_devid` NodeAttestor plugin (#2111, #2427)
- Caller details are now logged for unauthorized Server API calls (#2399)
- The `aws_iid` NodeAttestor plugin now supports attesting nodes across multiple AWS accounts via AWS IAM role assumption (#2387)
- Added support for running the `k8s_sat` NodeAttestor plugin with Kubernetes v1.21 (#2423)
- Call counter metrics are now emitted for SPIRE Server rate limiters (#2422)
- SPIRE Server now logs a message on startup when configured TTL values may result in SVIDs with a shorter lifetime than expected (#2284)

### Changed

- Updated a trust domain validation error message to mention that underscores are valid trust domain characters (#2392)

### Fixed

- Fixed bugs that broke the ACME bundle endpoint when using the `aws_kms` KeyManager plugin (#2390, #2397)
- Fixed a bug that resulted in SPIRE Agent sending unnecessary updates over the Workload API (#2305)
- Fixed a bug in the `k8s_psat` NodeAttestor plugin that prevented it from being configured with kubeconfig files (#2421)

## [1.0.0] - 2021-07-08

### Added

- The `vault` UpstreamAuthority plugin now supports Kubernetes service account authentication (#2356)
- A new `cert-manager` UpstreamAuthority plugin is now available (#2274)
- SPIRE Server CLI can now be used to ban agents (#2374)
- SPIRE Server CLI now has `count` subcommands for agents, entries, and bundles (#2128)
- SPIRE Server can now be configured for SPIFFE federation using the configurables defined by the spec (#2340)
- SPIRE Server and Agent now expose the standard gRPC health service (#2057, #2058)
- SPIFFE bundle endpoint URL is now configurable in the `federates_with` configuration block (#2340)
- SPIRE Agent may now optionally provided unregistered callers with a bundle for SVID validation via the `allow_unauthenticated_verifiers` configurable (#2102)
- SPIRE Server JWT key type is now independently configurable via `jwt_key_type` (#1991)
- Registration entries can now be queried/filtered by `federates_with` when calling the entry API (#1967)

### Changed

- SPIRE Server's SVID now uses the key type configured as `ca_key_type` (#2269)
- Caller address is now logged for agent API calls resulting in an error (#2281)
- Agent SVID renewals are now logged by the server at the INFO level (#2309)
- Workload API JWT-SVID profile will now return an error if the caller is unidentified (#2369)
- Workload API JWT-SVID profile will no longer return non-SPIFFE claims on validated JWTs from foreign trust domains (#2372)
- SPIRE artifact tarball no longer extracts `.` to avoid inadvertent changes in directory permisions (#2219)
- SPIRE Server default socket path is now `/tmp/spire-server/private/api.sock` (#2075)
- SPIRE Agent default socket path is now `/tmp/spire-agent/public/api.sock` (#2075)

### Deprecated

- SPIRE Server federation configuration in the `federates_with` `bundle_endpoint` block is now deprecated (#2340)
- SPIRE Server `gcp_iit` NodeAttestor configurable `projectid_whitelist` is deprecated in favor of `projectid_allow_list` (#2253)
- SPIRE Server `k8s_sat` and `k8s_psat` NodeAttestor configurable `service_account_whitelist` is deprecated in favor of `service_account_allow_list` (#2253)
- SPIRE Server `registration_uds_path`/`-registrationUDSPath` configurable and flag has been deprecated in favor of `socket_path`/`-socketPath` (#2075)

### Removed

- SPIRE Server no longer supports SPIFFE IDs with UTF-8 (#2368)
- SPIRE Server no longer supports the legacy Node API (#2093)
- SPIRE Server experimental configurable `allow_agentless_node_attestors` has been removed (#2098)
- The `aws_iid` NodeResolver plugin has been removed as it has been obviated (#2191)
- The `noop` NodeResolver plugin has been removed (#2189)
- The `proto/spire` go module has been removed in favor of the new SDKs (#2161)
- The deprecated `enable_sds` configurable has been removed (#2021)
- The deprecated `experimental bundle` CLI subcommands have been removed (#2062)
- SPIRE Server experimental configurables related to federation have been removed (#2062)
- SPIRE Server bundle endpoint no longer supports TLS signature schemes utilizing non-SHA256 hashes when ACME is enabled (#2397)

### Fixed

- Fixed a bug that caused health check failures in agents that have registration entries describing them (#2370)
- SPIRE Agent no longer logs a message when invoking a healthcheck via the CLI (#2058)
- Fixed a bug that caused federation to fail when using ACME in conjunction with the `aws_kms` KeyManager plugin (#2390)

## [0.12.3] - 2021-05-17

### Added

- The `k8s-workload-registrar` now supports federation (#2160)
- The `k8s_bundle` notifier plugin can now keep API service CA bundles up to date (#2193)
- SPIRE Server internal cache reload timing can now be tuned (experimental) (#2169)

### Changed

- Prometheus metrics that are emitted infrequently will no longer disappear after emission (#2239)
- The `k8s-workload-registrar` now uses paging to support very large deployments of 10,000+ pods (#2227)

### Fixed

- Fixed a bug that sometimes caused newly attested agents to not receive their full set of selectors (#2242)
- Fixed several bugs related to the handling of SPIRE Server API paging (#2251)

## [0.12.2] - 2021-04-14

### Added

- Added `aws_kms` server KeyManager plugin that uses the AWS Key Management Service (KMS) (#2066)
- Added `gcp_cas` UpstreamAuthority plugin that uses the Certificate Authority Service from Google Cloud Platform (#2172)
- Improved error returned during attestation of agents (#2159)
- The `aws_iid` NodeAttestor plugin now supports running in a location with no public internet access available for the server (#2119)
- The `k8s` notifier can now rotate Admission Controller Webhook CA Bundles (#2022)
- Rate limiting on X.509 signing and JWT signing can now be disabled (#2142)
- Added uptime metrics in server and agent (#2032)
- Calls to KeyManager plugins now time out at 30 seconds (#2044)
- Added logging when lookup of user by uid or group by gid fails in the `unix` WorkloadAttestor plugin (#2048)

### Changed

- The `k8s` WorkloadAttestor plugin now emits selectors for both image and image ID (#2116)
- HTTP readiness endpoint on agent now checks the health of the Workload API (#2015, #2087)
- SDS API in agent now returns an error if an SDS client requests resource names that don't exist (#2020)
- Bundle and k8s-workload-registrar endpoints now only accept clients using TLS v1.2+ (#2025)

### Fixed

- Registration entry update handling in CRD mode of the k8s-workload-registrar to prevent unnecessary issuance of new SVIDs (#2155)
- Failure to update CA bundle due to improper MySQL isolation level for read-modify-write operations (#2150)
- Regression preventing agent selectors from showing in `spire-server agent show` command (#2133)
- Issue in the token authentication method of the Vault Upstream Authority plugin (#2110)
- Reporting of errors in server entry cache telemetry (#2091)
- Agent logs an error and automatically shuts down when its SVID has expired and it requires re-attestation (#2065)

## [0.12.1] - 2021-03-04

### Security

- Fixed CVE-2021-27098
- Fixed CVE-2021-27099
- Fixed file descriptor leak in peertracker

## [0.12.0] - 2020-12-17

### Added

- Debug endpoints (#1792)
- Agent support for SDS v3 API (#1906)
- Improved metrics handling (#1885, #1925, #1932)
- Significantly improved performance related to performing agent authorization lookups (#1859, #1896, #1943, #1944, #1956)
- Database indexes to attested node columns (#1912)
- Support for configuring Vault roles, namespaces, and re-authentication to the Vault UpstreamAuthority plugin (#1871, #1981)
- Support for non-renewable Vault tokens to the Vault UpstreamAuthority plugin (#1965)
- Delete mode for federated bundles to the bundle API (#1897)
- The CLI now reads JSON from STDIN for entry create/update commands (#1905)
- Support for multiple CA bundle files in x509pop (#1949)
- Added `ExpiresAt` to `entry show` output (#1973)
- Added `k8s_psat:agent_node_ip` selector (#1979)

### Changed

- The agent now shuts down when it is no longer attested (#1797)
- Internals now rely on new server APIs (#1849, #1878, #1907, #1908, #1909, #1913, #1947, #1982, #1998, #2001)
- Workload API now returns a standardized JWKS object (#1904)
- Log message casing and punctuation are more consistent with project guidelines (#1950, #1952)

### Deprecated

- The Registration and Node APIs are deprecated, and a warning is logged on use (#1997)
- The `registration_api` configuration section is deprecated in favor of `server_api` in the k8s-workload-registrar (#2001)

### Removed

- Removed some superfluous or otherwise unusable metrics and labels (#1881, #1946, #2004)

### Fixed

- Fixed CLI exit codes when entry create or update fails (#1990)
- Fixed a bug that could cause external plugins to become orphaned processes after agent/server shutdown (#1962)
- Fixed handling of the Vault PKI certificate chain (#2012, #2017)
- Fixed a bug that could cause some gRPC libraries to fail to connect to the server over HTTP/2 (#1968)
- Fixed Registration API to validate selector syntax (#1919)

### Security

- JWT-SVIDs that fail validation are no longer logged (#1953)

## [0.11.3] - 2021-03-04

### Security

- Fixed CVE-2021-27098
- Fixed CVE-2021-27099
- Fixed file descriptor leak in peertracker

## [0.11.2] - 2020-10-29

### What's New

- Error messages related to a specific class of software bugs are now rate limited (#1901)

### What's Changed

- Fixed an issue in the Upstream Authority plugin that could result in a delay in the propagation of bundle updates/changes (#1917)
- Fixed error messages when attestation is disabled (#1899)
- Fixed some incorrectly-formatted log messages (#1920)

## [0.11.1] - 2020-09-29

### What's New

- Added AWS PCA configurable allowing operators to provide additional CA certificates for inclusion in the bundle (#1574)
- Added a configurable to server for disabling rate limiting of node attestation requests (#1794, #1870)

### What's Changed

- Fixed Kubernetes Workload Registrar issues (#1814, #1818, #1823)
- Fixed BatchCreateEntry return value to match docs, returning the contents of an entry if it already exists (#1824)
- Fixed issue preventing brand new deployments from downgrading successfully (#1829)
- Fixed a regression introduced in 0.11.0 that caused external node attestor plugins that rely on binary data to fail (#1863)

## [0.11.0] - 2020-08-28

### What's New

- Introduced refactored server APIs (#1533, #1548, #1563, #1567, #1568, #1571, #1575, #1576, #1577, #1578, #1582, #1585, #1586, #1587, #1588, #1589, #1590, #1591, #1592, #1593, #1594, #1595, #1597, #1604, #1606, #1607, #1613, #1615, #1617, #1622, #1623, #1628, #1630, #1633, #1641, #1643, #1646, #1647, #1654, #1659, #1667, #1673, #1674, #1683, #1684, #1689, #1690, #1692, #1693, #1694, #1701, #1708, #1727, #1728, #1730, #1733, #1734, #1739, #1749, #1753, #1768, #1772, #1779, #1783, #1787, #1788, #1789, #1790, #1791)
- Unix workloads can now be attested using auxiliary group membership (#1771)
- The Kubernetes Workload Registrar now supports two new registration modes (`crd` and `reconcile`)

### What's Changed

- Federation is now a stable feature (#1656, #1737, #1777)
- Removed support for the `UpstreamCA` plugin, which was deprecated in favor of the `UpstreamAuthority` plugin in v0.10.0 (#1699)
- Removed deprecated `upstream_bundle` server configurable. The server now always use the upstream bundle as the trust bundle (#1702)
- The server's AWS node attestor subsumed all the functionality of the node resolver, which has been deprecated (#1705)
- Removed pluggability of the DataStore interface, restricting use to the current built-in `sql` plugin (#1707)
- Unknown config options now make the server and agent fail to start (#1714)
- Improved registration entry change detection on agent (#1720)
- `/tmp/agent.sock` is now the default socket path for the agent (#1738)

## [0.10.2] - 2021-03-04

### Security

- Fixed CVE-2021-27098
- Fixed file descriptor leak in peertracker

## [0.10.1] - 2020-06-23

### What's New

- `vault` as Upstream Authority built-in plugin (#1611, #1632)
- Improved configuration file docs to list all possible configuration settings (#1608, #1618)

### What's Changed

- Improved container ID parsing from cgroup path in the `docker` workload attestor plugin (#1605)
- Improved container ID parsing from cgroup path in the `k8s` workload attestor plugin (#1649)
- Envoy SDS support is now always on (#1579)
- Errors on agent SVID rotation are now fatal if the agent's current SVID has expired, forcing an agent restart (#1584)

## [0.10.0] - 2020-04-22

- Added support for JWT-SVID in nested SPIRE topologies (#1388, #1394, #1396, #1406, #1409, #1410, #1411, #1415, #1416, #1417, #1423, #1440, #1455, #1458, #1469, #1476)
- Reduced database load under certain configurations (#1439)
- Agent now proactively rotates workload SVIDs in response to registration updates (#1441, #1477)
- Removed redundant telemetry counter in agent cache manager (#1445)
- Added environment variable config templating support (#1453)
- Added CreateEntryIfNotExists RPC to Registration API (#1464)
- The X.509 CA key now defaults to EC P-256 instead of EC P-384 (#1468)
- Added `validate` subcommand to the SPIRE Server and SPIRE Agent CLIs to validate the configuration file (#1471, #1489)
- Removed deprecated `ttl` configurable from upstreamauthority plugins (#1482)
- Fixed a bug which resulted in incorrect SHA for certain types of workloads (#1405)
- OIDC Discovery Provider now supports listening on a Unix Domain Socket (#1408)
- Fixed a bug that could lead to agent eviction if a crash occurred during agent SVID rotation (#1399)
- The `upstream_bundle` configurable now defaults to true, and is marked as deprecated (#1404)
- OIDC Discovery Provider and the Kubernetes Workload Registrar release binaries are now available via the `spire-extras` tarball (#1424)
- Introduced new plugin type UpstreamAuthority, which supports both X509-SVID and JWT-SVID as well as the ability to push upstream changes into SPIRE Server (#1388, #1394, #1406, #1455)
- AWS PCA, AWS Secrets, Disk and SPIRE UpstreamCA plugins have been ported to the UpstreamAuthority type (#1411, #1409, #1410, #1415)
- Introduced a new RPC `PushJWTKeyUpstream` in the Node API for publishing JWT-SVID signing keys from downstream servers (#1416)
- Introduced a new RPC `FetchBundle` in the Node API for fetching an up-to-date bundle (#1458)
- AWS PCA UpstreamAuthority plugin endpoint is now configurable (#1498)
- The UpstreamCA plugin type is now marked as deprecated in favor of the UpstreamAuthority plugin type (#1406)

## [0.9.4] - 2021-03-04

### Security

- Fixed CVE-2021-27098
- Fixed file descriptor leak in peertracker

## [0.9.3] - 2020-03-05

- Significantly reduced the server's database load (#1350, #1355, #1397)
- Improved consistency in SVID propagation time for some cases (#1352)
- AWS IID node attestor now supports the v2 metadata service (#1369)
- SQL datastore plugin now supports leveraging read-only replicas (#1363)
- Fixed a bug in which CA certificates may have an empty Subject if incorrectly configured (#1387)
- Server now logs an agent ID when an invalid agent makes a request (#1395)
- Fixed a bug in which the server CLI did not correctly show entries when querying with multiple selectors (#1398)
- Registration API now has an RPC for listing entries that supports paging (#1392)

## [0.9.2] - 2020-01-14

- Fixed a crash when a key protecting the bundle endpoint is removed (#1326)
- Bundle endpoint client now supports Web-PKI authenticated endpoints (#1327)
- SPIRE now warns if the CA TTL will result in shorter-than-expected SVID lifetimes (#1294)

## [0.9.1] - 2019-12-19

- Agent cache file writes are now atomic, more resilient (#1267)
- Introduced Google Cloud Storage bundle notifier plugin for server (#1227)
- Server and agent now detect unknown configuration options in supported blocks (#1289, #1299, #1306, #1307)
- Improved agent response to heavy server load through use of request backoffs (#1270)
- The in-memory telemetry sink can now be disabled, and will be by default in a future release (#1248)
- Agents will now re-balance connections to servers (and re-resolve DNS) automatically (#1265)
- Improved behavior of M3 duration telemetry (#1262)
- Fixed a bug in which MySQL deadlock may occur under heavy attestation load (#1291)
- KeyManager "disk" now emits a friendly error when directory option is missing (#1313)

## [0.9.0] - 2019-11-14

- Users can now opt-out of workload executable hashing when enabling the workload path as a selector (#1078)
- Added M3 support to telemetry and other telemetry and logging improvements (#1059, #1085, #1086, #1094, #1102, #1122,#1138,#1160,#1186,#1208)
- SQL auto-migration can be disabled (#1089)
- SQL schema compatibility checks are aligned with upgrade compatibility guarantees (#1089)
- Agent CLI can provide information on attested nodes (#1098)
- SPIRE can tolerate small SVID expiration periods (#1115)
- Reduced Docker image sizes by roughly 25% (#1140)
- The `upstream_bundle` configurable is deprecated (#1147)
- Agents can be configured to bootstrap insecurely with SPIRE Servers for ease of evaluation (#1148)
- The issuer claim in JWT-SVIDs can be customized (#1164)
- SPIRE Server supports a wider variety of signing key types (#1169)
- New OIDC discovery provider that serves a compatible JWKS document with signing keys from the trust domain (#1170,#1175)
- New Upstream CA plugin that signs SPIRE Server CA CSRs using a Private Ceriticate Authority in AWS Certificate Manager (#1172)
- Agents respond more predictably when making requests to an overloaded SPIRE Server (#1182)
- Docker Workload Attestor supports a wider variety of cgroup drivers (#1188)
- Docker Workload Attestor supports selection based on container environment variables (#1205)
- Fixed an issue in which Kubernetes workload attestation occasionally fails to identify the caller (#1216)

## [0.8.5] - 2021-03-04

### Security

- Fixed CVE-2021-27098
- Fixed file descriptor leak in peertracker

## [0.8.4] - 2019-10-28

- Fixed spurious agent synchronization failures during agent SVID rotation (#1084)
- Added support for [Kind](https://kind.sigs.k8s.io) to the Kubernetes Workload Attestor (#1133)
- Added support for ACME v2 to the bundle endpoint (#1187)
- Fixed a bug that could result in agent crashes after upgrading to 0.8.2 or newer (#1194)

## [0.8.3] - 2019-10-18

- Upgrade to Go 1.12.12 in response to CVE-2019-17596 (#1204)

## [0.8.2] - 2019-10-10

- Connection pool details in SQL DataStore plugin are now configurable (#1028)
- SQL DataStore plugin now emits telemetry (#998)
- The SPIFFE bundle endpoint now supports serving Web PKI via ACME (#1029)
- Fix Workload API socket permissions when enclosing directory is automatically created (#1048)
- The Kubernetes PSAT node attestor now emits node and pod label selectors (#1042)
- SVIDs can now be created directly against SPIRE server using the new `mint` feature (#1036)
- SPIRE agent behavior improved to more efficiently balance load across SPIRE servers (#1061)
- Significant SQL DataStore performance improvements (#1069, #1079)
- Kubernetes workload registrar now supports assigning SPIFFE IDs based on an annotation (#1047)
- Registration entries with an expiry set are now automatically pruned from the datastore (#1056)
- Fix bug that resulted in authorized workloads being denied SVIDs (#1103)

## [0.8.1] - 2019-07-19

- Failure to obtain peer information from a Workload API connection no longer brings down the agent (#946)
- Agent now detects expired cached SVID when it starts and will attempt to re-attest instead of failing (#1000)
- GCP IIT-based node attestation produces selectors for the project, zone, instance name, tags, service accounts, metadata and labels (#969, #1006, #1012)
- X.509 certificate serial numbers are now random 128-bit numbers (#999)
- Added SQL table indexes to SQL datastore to improve query performance (#1007)
- Improved metrics coverage (#931, #932, #935, #968)
- Plugins can now emit metrics (#990, #993)
- GCP CloudSQL support (#995)
- Experimental support for SPIFFE federation (#951, #983)
- Fixed a peertracker bug parsing /proc/PID/stat on Linux (#982)
- Fixed a bug causing occasional panics on shutdown when running on a BSD-based system (#970)
- Fixed a bug in the unix workload attestor failing attestation if the user or group lookup failed (#973)
- Server plugins can now query for attested agent information (#964)
- AWS Secrets UpstreamCA plugin can now authenticate to AWS via a Role ARN (#938, #963)
- K8S Workload Attestor now works with Docker's systemd cgroup driver (#950)
- Improved documentation and examples (#915, #916, #918, #926, #930, #940, #941, #948, #954, #955, #1014)
- Fixed SSH-based node attested agent IDs to be URL-safe (#944)
- Fixed bug preventing agent bootstrapping when an UpstreamCA is used in conjunction with `upstream_bundle = false` (#939)
- Agent now properly handles signing SVIDs for multiple registration entries mapped to the same SPIFFE ID (#929)
- Agent Node Attestor plugins no longer have to determine the agent ID (#922)
- GCP IIT node attestor can now be configured with the host used to obtain the token (#917)
- Fixed race in bundle pruning for HA deployments (#919)
- Disk UpstreamCA plugin now supports intermediate CAs (#910)
- Docker workload attestation now retries connections to the Docker deamon on transient failures (#901)
- New Kubernetes Workload Registrar that automatically registers Kubernetes workloads (#885, #953)
- Logs can now be emitted in JSON format (#866)

## [0.8.0] - 2019-05-20

- Fix a bug in which the agent periodically logged connection errors (#906)
- Kubernetes SAT node attestor now supports the TokenReview API (#904)
- Agent cache refactored to improve memory management and fix a leak (#863)
- UpstreamCA "disk" will now reload cert and keys when needed (#903)
- Introduced Nested SPIRE: server clusters can now be chained together (#890)
- Fix a bug in AWS IID NodeResolver with instance profile lookup (#888)
- Improved workload attestation and fixed a security bug related to PID reuse (#886)
- New Kubernetes bundle notifier for keeping a bundle configmap up-to-date (#877)
- New plugin type Notifier for programmatically taking action on important events (#877)
- New NodeAttestor based on SSH certificates (#868, #870)
- v2 client library for Workload API interaction (#841)
- Back-compat bundle management code removed - bundle is now handled correctly (#858, #859)
- Plugins can now expose auxiliary services and consume host-based services (#840)
- Fix bug preventing agent recovery prior to its first SVID rotation (#839)
- Agent and server can now export telemetry to Prometheus, Statsd, DogStatsd (#817)
- Fix bug in SDS API that prevented updates following Envoy restart (#820)
- Kubernetes workload attestor now supports using the secure port (#814)
- Support for TLS-protected connections to MySQL (#821)
- X509-SVID can now include an optional CN/DNS SAN (#798)
- SQL DataStore plugin now supports MySQL (#784)
- Fix bug preventing agent from reconnecting to a new server after an error (#795)
- Fix bug preventing agent from shutting down when streams are open (#790)
- Registration entries can now have an expiry and be pruned automatically (#776, #793)
- New Kubernetes NodeAttestor based on PSAT for node specificity (#771, #860)
- New UpstreamCA plugin for AWS secret manager (#751)
- Healthcheck commands exposed in server and agent (#758, #763)
- Kubernetes workload attestor extended with additional selectors (#720)
- UpstreamCA "disk" now supports loading multiple key types (#717)

## [0.7.3] - 2019-02-11

- Agent can now expose Envoy SDS API for TLS certificate installation rotation (#667)
- Agent now automatically creates its configured data dir if it doesn't exist (#678)
- Agent panic fixed in the event that rotation is attempted from non-attested node (#684)
- Docker workload attestor plugin introduced (#687)
- Agent and server no longer force a configured umask, upgrades it if too permissive (#686)
- Registration entry CLI utility now supports --node entry distinction (#695)
- Server can now evict previously-attested agents (#693)
- Official docker images are now published on build and release (#700)

## [0.7.2] - 2019-01-23

- Fix non-random UUID bug by moving to gofrs-maintained uuid pkg (#659)
- Server now supports multiple node resolvers (#652)
- Server no longer allows agent to specify X.509 Subject value (#663)
- Registration API is now authenticated, can be reached remotely (#656)
- Fixed debug log message in the Node API handler (#666)
- Agent's KeyManager interface updated for better durability (#669)
- Use FQDN in the GCP Node Attestor to prevent reliance on shortname resolution (#672)
- Upgrade to Go 1.11.5 in response to CVE-2019-6486 (#690)

## [0.7.1] - 2018-12-20

- Documentation updates for Azure plugins, agent, server (#629, #631, #642, #651, #654)
- Intermediate certificates now included in bundle for compatibility with 0.6 (#633)
- Attestation now fails if NodeResolver encounters an error (#634)
- Fix bootstrap bug when `upstream_bundle` is not set (#639)
- Additional telemetry points added, introduced telemetry in server (#640)
- CLI utilities now print TTL value of `default` instead of `0` when not set (#645)
- Fix bug in CLI utilities causing them to write PEM files with the wrong header (#647)
- Go runtime upgraded in response to CVE-2018-16875 (#653)
- Server now detects and prevents trust domain configuration change (#644)
- Fix vulnerability in which X.509 path validation is not performed on node API (#655)

## [0.7.0] - 2018-11-08

- JWT Support (#616)
- Workload API now returns intermediate chains (#611)
- UNIX attestor now returns binary path and sha256 (#590)
- UNIX attestor now returns effective user and group name (#589)
- Node API now ratelimits expensive calls (#577)
- Soft delete disabled in SQL datastore plugin (#560)
- Basic federation support (#559, #563, #581, #582)
- Kubernetes node attestor (#557)
- AWS node resolver builtin (#554)
- Azure node attestor (#551)
- Azure node resolver (#553)
- KeyManager plugin interface for server (#539)
- Disk-based KeyManager server plugin (#532)
- x509pop now supports intermediate chains (#524)
- Fix bug that resulted in some SVIDs outliving CA (#520)
- Let agent fail over to different server on failure (#561)
- Node attestors can now return selectors (#516)
- Improved SPIFFE ID validation (#513, #515)

## [0.6.2] - 2018-09-12

- Support for Azure node attestation (#551)
- Support for Azure node resolution (#553)
- Updated DNS resolution to support DNS-based HA failover (#561)
- Updated x509pop challenge to strengthen against signature replay attacks (#562)
- Removed sql plugin soft delete for better space management (#560)
- Performance improvements and bugfixes in sql plugin (#564)
- Support for HTTP/HTTPS CONNECT proxies (#568, #585)
- Updated Node API to perform ratelimiting (#577)

## [0.6.1] - 2018-07-27

- Fixed SVID renewal bug (#520)
- Support separate file for intermediates in x509pop node attestor (#524)
- Allow node attestors to provide supplemental selectors (#516)
- ServerCA "memory" can now optionally persist keys to disk (#532)
- Config file updates so spire commands can be run from any CWD (#541)
- Minor doc/example fixes (#535)

## [0.6.0] - 2018-06-26

- Added GCP Instance Identity Token (IIT) node attestation.
- Added X509 Proof-of-Possession node attestation.
- Added challenge/response support to node attestation API.
- SQL datastore plugin renamed. Now includes support for PostgresSQL.
- Improved k8s workload attestation resilience.
- Lots of bug fixes.
