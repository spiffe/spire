# CHANGELOG Guidelines

The following guidelines should be followed when updating the CHANGELOG:

- There should be an entry for every version, that includes the version number and release date.
- Entries should be focused on communicating user-facing changes, considering that the main consumers of the CHANGELOG are the end users of SPIRE.
- The types of changes should be grouped using the following categories:
  - **Added**: New features that impact in the user experience. Should clearly communicate the new capability and why it is good.
  - **Changed**: Changes in existing functionality. Should include information about the components affected and any behavioral changes.
  - **Deprecated**: Features that will be removed in a future release. Should communicate any planned behavioral changes, including if the feature is deprecated in favor of a different feature.
  - **Removed**: Features removed in this release. Should describe any behavioral changes, including if the feature has been removed in favor of a different feature.
  - **Fixed**: Regular bug fixes. Should describe what the user would be experiencing if they were encountering the issue that is now fixed.
  - **Security**: Security-related fixes. If there is a CVE assigned, it should be included.

Categories that don't have an entry for the release are omitted in the CHANGELOG.

The following is an example that includes all the categories:

## [a.b.c] - YYYY-MM-DD

### Added

- AWS PCA now has a configurable allowing operators to provide additional CA certificates for inclusion in the bundle (#1574)

### Changed

- Envoy SDS support is now always on (#1579)

### Deprecated

- The UpstreamCA plugin type is now marked as deprecated in favor of the UpstreamAuthority plugin type (#1406)

### Removed

- The deprecated `upstream_bundle` server configurable has been removed. The server always uses the upstream bundle as the trust bundle (#1702)

### Fixed

- Issue in the Upstream Authority plugin that could result in a delay in the propagation of bundle updates/changes (#1917)

### Security

- Node API now ratelimits expensive calls (#577)
