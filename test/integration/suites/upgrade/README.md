# Upgrade Suite

## Description

This suite tests a simple upgrade step from SPIRE from one version to the next.

It does the following in order:

1. Brings up the _old_ SPIRE server and agent
1. Obtains an SVID from the _old_ agent
1. Upgrades the SPIRE server
1. Obtains an SVID from the _old_ agent (making sure it has rotated)
1. Upgrades the SPIRE agent
1. Obtains an SVID from the _new_ agent (making sure it has rotated)

### Upgrading SPIRE Server/Agent

The _upgrade_ is performed by bringing down the container running the _old_
version and starting the container running the _new_ version. The containers
share configuration and data directory via a series of shared volumes.

### Checking for rotation

To check for rotation, the SVID is written to disk at each step. It is then
checked against the SVID for the previous step to make sure it has been
rotated.

### Maintenance

When making a SPIRE release, the versions.txt should be updated to add the new
version, ideally as part of the first commit after release that bumps the base
version in pkg/common/version/version.go.

When preparing to release a new "major" release (_minor_ release pre-1.0), the
versions.txt file should be updated to remove the "major"-2 versions, since we
only support upgrading from one "major" build to the next. For example, if the
versions.txt file contained all 0.8.x and 0.9.x versions, the 0.8.x versions
should be removed as part of the 0.10.0 release.

## Future considerations

- Provide additional "+/- 1" SPIRE compatibility checks, as currently we only
  test that the SPIRE components start up and that SVIDs rotate.
