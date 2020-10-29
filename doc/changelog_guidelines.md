# CHANGELOG Guidelines

- CHANGELOG entries should be focused on communicating user-facing changes, considering that the main consumers of the CHANGELOG are the end users of SPIRE.
- There should be an entry for every version, that includes the version number and release date.
- The types of changes should be grouped using the following categories:
  - **Added**: New features that impact in the user experience.
  - **Changed**: Changes in existing functionality.
  - **Deprecated**: Features that will be removed in a future release.
  - **Removed**: Features removed in this realease.
  - **Fixed**: Regular bug fixes. Should describe what the user would be experiencing if they were encountering the issue that is now fixed.
  - **Security**: Security-related fixes. It should preciselly describe what released versions are affected, what are the components affected and under which circumstances. It should also be noted what is the impact of the issue and if there there is a way to mitigate the issue in unpatched versions.

Categories that don't have an entry for the release are omitted in the CHANGELOG.


## Sample

## [0.11.1] - 2020-09-29

### What's New
- Added AWS PCA configurable allowing operators to provide additional CA certificates for inclusion in the bundle (#1574)
- Added a configurable to server for disabling rate limiting of node attestation requests (#1794, #1870)

### What's Changed
- Fixed Kubernetes Workload Registrar issues (#1814, #1818, #1823)
- Fixed BatchCreateEntry return value to match docs, returning the contents of an entry if it already exists (#1824)
- Fixed issue preventing brand new deployments from downgrading successfully (#1829)
- Fixed a regression introduced in 0.11.0 that caused external node attestor plugins that rely on binary data to fail (#1863)

