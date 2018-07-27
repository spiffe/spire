# Changelog

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
