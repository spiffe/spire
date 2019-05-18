# Changelog

## [0.8.0] - 2019-05-20
- Fix a bug in which the agent periodically logged connection errors (#906)
- Kubernetes SAT node attestor now supports the TokenReview API (#904)
- Agent cache refactored to improve memory management and fix a leak (#863)
- UpstreamCA "disk" will now reload cert and keys when needed (#903)
- Introduced Nested SPIRE: server clusters can now be chained together (#890)
- Fix a bug in AWS IID NodeResolver with instance profile lookup (888)
- Improved workload attestation and fixed a security bug related to PID reuse (#886)
- New Kubernetes bundle notifier for keeping a bundle configmap up-to-date (#877)
- New plugin type Notifier for programatically taking action on important events (#877)
- New NodeAttestor based on SSH certificates (#868, #870)
- v2 client library for Workload API interaction (#841)
- Back-compat bundle management code removed - bundle is now handled correctly (#858, #859)
- Plugins can now expose auxiliary services and consume host-based services (#840)
- Fix bug preventing agent recovery prior to its first SVID rotation (#839)
- Agent and Server can now export telemetry to Prometheus, Statsd, DogStatsd (#817)
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
- Healthcheck commands exposed in Server and Agent (#758, #763)
- Kubernetes workload attestor extended with additional selectors (#720)
- UpstreamCA "disk" now supports loading multiple key types (#717)

## [0.7.3] - 2019-02-11
- Agent can now expose Envoy SDS API for TLS certificate installation rotation (#667)
- Agent now automatically creates its configured data dir if it doesn't exist (#678)
- Agent panic fixed in the event that rotation is attempted from non-attested node (#684)
- Docker workload attestor plugin introduced (#687)
- Agent and Server no longer force a configured umask, upgrades it if too permissive (#686)
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
