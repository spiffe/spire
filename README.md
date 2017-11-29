![Build Status](https://travis-ci.org/spiffe/spire.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/spire/badge.svg?branch=master)](https://coveralls.io/github/spiffe/spire?branch=master)

![SPIRE Logo](/doc/images/spire_logo.png)

SPIRE (the [SPIFFE](https://github.com/spiffe/spiffe) Runtime Environment) provides a toolchain that defines a central registry of
SPIFFE IDs (the Server), and a Node Agent that can be run adjacent to a workload and
exposes a local Workload API. To get a better idea of what SPIRE is, and how it works, here is a [video](https://www.youtube.com/watch?v=uDHNcZ0eGHI) of it in action.

Please note that the SPIRE project is pre-alpha. It is under heavy development, and is NOT suitable for production use. See the [open issues](https://github.com/spiffe/spire/issues) or drop by our [Slack channel](https://slack.spiffe.io/) for more information.

# Installing SPIRE

There are several ways to install the SPIRE binaries:

* Binary releases can be found at https://github.com/spiffe/spire/releases
* [Building from source](/CONTRIBUTING.md)

# Configuring SPIRE

## SPIRE agent

See [doc/spire_agent.md](/doc/spire_agent.md)

## SPIRE server

See [doc/spire_server.md](/doc/spire_server.md)


# Community

The SPIFFE community, and [Scytale](https://scytale.io) in particular, maintain the SPIRE project.
Information on the various SIGs and relevant standards can be found in
https://github.com/spiffe/spiffe.

The SPIFFE and SPIRE governance policies are detailed in
[GOVERNANCE](https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md)
