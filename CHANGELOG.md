# Changelog

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
