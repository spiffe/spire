# Managing Upgrades/Downgrades
This guide describes how to upgrade your SPIRE deployment, as well as the compatibility guarantees that SPIRE users can expect.

## SPIRE Versioning
SPIRE versions are expressed as **x.y.z**, where **x** is the major version, **y** is the minor version, and **z** is the patch version, following Semantic Versioning terminology. Despite the fact that the project is currently pre-1.0, version compatibility guarantees are already in place. This document will be updated in advance of a 1.0.0 release.

### SPIRE Server Compatibility
Version skew within a SPIRE Server cluster is supported within +/- 1 minor version. In other words, the newest and oldest SPIRE Server instances in any given cluster must be within one minor version of each other.

For example:
* Newest SPIRE Server instance is at 0.9.3
* Other SPIRE Server instances are supported at 0.9.x and 0.8.x

### SPIRE Agent Compatibility
SPIRE Agents must not be newer than the oldest SPIRE Server that they communicate with, and may be up to one minor version older.

For example:
* SPIRE Servers are at both 0.9.3 and 0.9.2
* SPIRE Agents are supported at 0.8.0 through 0.9.2

### SPIRE Plugin Compatibility
SPIRE plugins generally follow the same overall guarantees as all other SPIRE components with small exception for changes made to external plugins outside of SPIRE's control.

#### Configuration and Behavior Compatibility
A built-in plugin undergoing a backwards incompatible change (e.g. change to configuration semantics, change to selectors produced, etc.) should log a warning but otherwise maintain backwards compatibility for one minor version after the change is introduced, giving operators time to adopt requisite changes.
SPIRE cannot make any guarantees around configuration or behavior compatibility for external plugins.

#### Interface Compatibility
All efforts will be made to introduce changes to plugin interfaces in a backwards compatible manner. If a breaking change is introduced to a plugin interface, existing plugins compiled against the old interface will still continue to function for one minor version release cycle to give operators time to adopt requisite changes. SPIRE will log warnings to make operators aware of the change.

## Supported Upgrade Paths

The supported version skew between SPIRE Servers and agents has implications on the order in which they must be upgraded. SPIRE Servers must be upgraded before SPIRE Agents, and is limited to a jump of at most one minor version (regardless of patch version). Upgrades that jump two or more minor versions (e.g. 0.8.1 to 0.10.0) are not supported.

SPIRE Server and agent instances may be upgraded in a rolling fashion.

For example, if upgrading from 0.8.1 to 0.9.3:
* Upgrade SPIRE Server instances from 0.8.1 to 0.9.3 one instance at a time
* Ensure that the SPIRE Server cluster is operating as expected
* Upgrade SPIRE Agent instances from 0.8.1 to 0.9.3 one instance at a time or in batches

Note that while a rolling upgrade is highly recommended, it is not strictly required. SPIRE Server supports zero-downtime upgrades so long as there is more than one SPIRE Server in the cluster.

## Supported Downgrade Paths

SPIRE supports downgrading in the event that a problem is encountered while rolling out an upgrade. Since agents can't be newer than the oldest server they communicate with, it is necessary to first downgrade agents before downgrading servers, assuming that the agents have already been upgraded. For this reason, it is a good idea to ensure that the upgraded SPIRE Servers are operating as expected prior to upgrading the agents.

For example, if downgrading from version 0.9.3 to 0.8.1:
* Downgrade SPIRE Agent instances from 0.9.3 to 0.8.1 one at a time or in batches
* Downgrade SPIRE Server instances from 0.9.3 to 0.8.1 one at a time

Note that while a rolling downgrade is highly recommended, it is not strictly required. SPIRE Server supports zero-downtime downgrades so long as there is more than one SPIRE Server in the cluster.
