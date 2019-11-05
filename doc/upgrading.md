# Managing Upgrades/Downgrades
This guide describes how to upgrade your SPIRE deployment, as well as the compatibility guarantees that SPIRE users can expect.

## SPIRE Versioning
SPIRE versions are expressed as **x.y.z**, where **x** is the major version, **y** is the minor version, and **z** is the patch version, following Semantic Versioning terminology. The SPIRE project is currently pre-1.0, so minor SPIRE releases act like major releases and patch releases act like minor releases. Despite the fact that the project is pre-1.0, version compatibility guarantees are already in place.

### SPIRE Server Compatibility
Version skew within a SPIRE server cluster is supported within +/- 1 minor version. In other words, the newest and oldest SPIRE server instances in any given cluster must be within one minor version of each other.

For example:
* Newest SPIRE server instance is at 0.9.3
* Other SPIRE server instances are supported at 0.9.x and 0.8.x

### SPIRE Agent Compatibility
SPIRE agents must not be newer than the oldest SPIRE server that they communicate with, and may be up to one minor version older.

For example:
* SPIRE servers are at both 0.9.3 and 0.9.2
* SPIRE agents are supported at 0.8.0 through 0.9.2

## Supported Upgrade Paths

The supported version skew between SPIRE servers and agents has implications on the order in which they must be upgraded. SPIRE servers must be upgraded before SPIRE agents, and is limited to a jump of at most one minor version (regardless of patch version). SPIRE server and agent instances may be upgraded in a rolling fashion.

For example, if upgrading from 0.8.1 to 0.9.3:
* Upgrade SPIRE server instances from 0.8.1 to 0.9.3 one at a time
* Ensure that the SPIRE server cluster is operating as expected
* Upgrade SPIRE agent instances from 0.8.1 to 0.9.3 one at a time or in batches

Note that while a rolling upgrade is highly recommended, it is not strictly required. SPIRE server supports zero-downtime upgrades so long as there is more than one SPIRE server in the cluster.

## Supported Downgrade Paths

SPIRE supports downgrading in the event that a problem is encountered while rolling out an upgrade. Since agents can't be newer than the oldest server they communicate with, it is necessary to first downgrade agents before downgrading servers, assuming that the agents have already been upgraded. For this reason, it is a good idea to ensure that the upgraded SPIRE servers are operating as expected prior to upgrading the agents.

For example, if downgrading from version 0.9.3 to 0.8.1:
* Downgrade SPIRE agent instances from 0.9.3 to 0.8.1 one at a time or in batches
* Downgrade SPIRE server instances from 0.9.3 to 0.8.1 one at a time

Note that while a rolling downgrade is highly recommended, it is not strictly required. SPIRE server supports zero-downtime downgrades so long as there is more than one SPIRE server in the cluster.
