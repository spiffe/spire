# Upgrade Suite

## Description

This suite tests a simple upgrade step from SPIRE from one version to the next.

It does the following in order:

1. Brings up the old SPIRE server and agent
1. Obtains an SVID from the agent
1. Upgrades the SPIRE server
1. Obtains an SVID from the agent (making sure it has rotated)
1. Upgrades the SPIRE agent
1. Obtains an SVID from the agent (making sure it has rotated)

### Upgrading SPIRE Server/Agent

The "upgrade" is performed by bringing down the container running the old
version and starting the container running the new version. The containers
share configuration and data directory via a series of shared volumes.

### Checking for rotation

To check for rotation, the SVID is written to disk at each step. It is then
checked against the SVID for the previous step to make sure it has been
rotated.

## Future considerations

- Provide stronger "+/- 1" SPIRE compatability checks.
- Automatically use the last release for the OLD version (right now the version is hard coded in the docker-compose.yaml)
