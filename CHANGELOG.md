# Changelog

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
- New plugin type Notifier for programatically taking action on important events (#877)
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
