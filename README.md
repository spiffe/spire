![SPIRE Logo](/doc/images/spire_logo.png)

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3303/badge)](https://bestpractices.coreinfrastructure.org/projects/3303)
[![Build Status](https://travis-ci.org/spiffe/spire.svg?branch=master)](https://travis-ci.org/spiffe/spire)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/spire/badge.svg?branch=master)](https://coveralls.io/github/spiffe/spire?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/spiffe/spire)](https://goreportcard.com/report/github.com/spiffe/spire)
[![Slack Status](https://slack.spiffe.io/badge.svg)](https://slack.spiffe.io)

SPIRE (the [SPIFFE](https://github.com/spiffe/spiffe) Runtime Environment) is a tool-chain for establishing trust between software systems across a wide variety of hosting platforms. Concretely, SPIRE exposes the [SPIFFE Workload API](https://github.com/spiffe/go-spiffe/blob/master/proto/spiffe/workload/workload.proto), which can attest running software systems and issue [SPIFFE IDs](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md) and [SVID](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md)s to them.  This in turn allows two workloads to establish trust between each other, for example by establishing an mTLS connection or by signing and verifying a JWT token. Or for a workload to securely authenticate to a secret store, a database, or a cloud provider service.


- [Get SPIRE](#get-spire)
- [Getting started](#getting-started)
- [Examples](#examples)
- [Using SPIRE with Envoy](#using-spire-with-envoy)
- [Getting help](#getting-help)
- [Community](#community)

# Get SPIRE

Pre-built releases can be found at [https://github.com/spiffe/spire/releases](https://github.com/spiffe/spire/releases). These releases contain both server and agent binaries plus the officially supported plugins.

Alternatively you can [build SPIRE from source](/CONTRIBUTING.md).

# Getting started

Before trying out SPIRE, we recommend becoming familiar with its [architecture](https://spiffe.io/spire/) and design goals.

[Getting Started Guide for Kubernetes](https://spiffe.io/spire/getting-started-k8s)

[Getting Started Guide for Linux](https://spiffe.io/spire/getting-started-linux/)

The [SPIRE Server](https://github.com/spiffe/spire/blob/master/doc/spire_server.md) and [SPIRE Agent](https://github.com/spiffe/spire/blob/master/doc/spire_agent.md) reference guides covers in more detail the specific configuration options and plugins available.

# Examples

There are several examples demonstrating SPIRE usage in the [spire-examples](https://github.com/spiffe/spire-examples) repository.

# Using SPIRE with Envoy

SPIRE provides an implementation of the [Envoy](https://envoyproxy.io)
[Secret Discovery Service](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret)
(SDS). SDS can be used to transparently install and rotate TLS certificates and
trust bundles in Envoy. Please see the [SPIRE Agent configuration guide](/doc/spire_agent.md#agent-configuration-file) for more information.

# Getting Help

If you have any questions about how SPIRE works, or how to get it up and running, the best place to ask questions is the [SPIFFE Slack Organization](https://slack.spiffe.io/). Most of the maintainers monitor the #spire channel there, and can help direct you to other channels if need be. Please feel free to drop by any time!

# Community

The SPIFFE community, and [Scytale](https://scytale.io) in particular, maintain the SPIRE project.
Information on the various SIGs and relevant standards can be found in
https://github.com/spiffe/spiffe.

The SPIFFE and SPIRE governance policies are detailed in
[GOVERNANCE](https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md).

