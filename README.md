[![Build Status](https://travis-ci.com/spiffe/spire.svg?token=pXzs6KRAUrxbEXnwHsPs&branch=master)](https://travis-ci.com/spiffe/spire)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/spire/badge.svg?branch=master&t=GWBRCP)](https://coveralls.io/github/spiffe/spire?branch=master)

![SPIRE Logo](/doc/spire_logo.png)

SPIRE (the SPIFFE Runtime Environment) provides a toolchain that defines a central registry of
SPIFFE IDs (the Server), and a Node Agent that can be run adjacent to a workload and
exposes a local Workload API.

# Getting started

## Installing SPIRE

`go get github.com/spiffe/spire/...` will fetch and build all of SPIRE and its
dependencies and install them in $GOPATH/bin

## Configuring SPIRE

See the [server README](/cmd/spire-server/README.md) and the [agent
README](/cmd/spire-agent/README.md)

# Building SPIRE

See [CONTRIBUTING](CONTRIBUTING.md) for information on building and developing SPIRE.

# Community

The SPIFFE community, and [Scytale](https://scytale.io) in particular, maintain the SPIRE project.
Information on the various SIGs and relevant standards can be found in
https://github.com/spiffe/spiffe.

The SPIFFE and SPIRE governance policies are detailed in [GOVERNANCE](https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md)
