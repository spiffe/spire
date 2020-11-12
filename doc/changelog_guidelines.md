# CHANGELOG Guidelines

The following guidelines should be followed when updating the CHANGELOG:
- There should be an entry for every version, that includes the version number and release date.
- Entries should be focused on communicating user-facing changes, considering that the main consumers of the CHANGELOG are the end users of SPIRE.
- The types of changes should be grouped using the following categories:
  - **Added**: New features that impact in the user experience.
  - **Changed**: Changes in existing functionality.
  - **Deprecated**: Features that will be removed in a future release.
  - **Removed**: Features removed in this release.
  - **Fixed**: Regular bug fixes. Should describe what the user would be experiencing if they were encountering the issue that is now fixed.
  - **Security**: Security-related fixes.

Categories that don't have an entry for the release are omitted in the CHANGELOG.

The following is an example that includes all the categories:

## [a.b.c] - YYYY-MM-DD

### Added
- AWS PCA now has a configurable allowing operators to provide additional CA certificates for inclusion in the bundle (#1574)

### Changed
- Envoy SDS support is now always on (#1579)

### Deprecated
- The `upstream_bundle` configurable now defaults to true, and is marked as deprecated (#1404)

### Removed
- The deprecated `upstream_bundle` server configurable has been removed. The server always uses the upstream bundle as the trust bundle (#1702)

### Fixed
- Issue in the Upstream Authority plugin that could result in a delay in the propagation of bundle updates/changes (#1917)

### Security
- Node API now ratelimits expensive calls (#577)
