# Getting started Ubuntu 16.04

<!-- TOC -->

- [Getting started Ubuntu 16.04](#getting-started-ubuntu-1604)
    - [SPIRE Ubuntu installation](#spire-ubuntu-installation)
    - [Building the artifacts](#building-the-artifacts)
    - [Installing your artifact](#installing-your-artifact)
    - [Configuration](#configuration)
    - [Running SPIRE with join token](#running-spire-with-join-token)

<!-- /TOC -->

## SPIRE Ubuntu installation

You can either download the binaries from [here](https://github.com/spiffe/spire/releases) or build them by
[setting up your dev environment](https://github.com/spiffe/spire/blob/master/CONTRIBUTING.md).

## Building the artifacts

Note: If you are downloading the artifacts you can skip this step.

In order to build the package you need to do:

    $ make vendor
    $ make buid
    $ ./build.sh artifact

This will put the result in the artifacts directory.

## Installing your artifact

Copy your downloaded or generated package into **/opt**

    $ sudo cp your_package.tgz /opt/
    $ sudo rm -rf your_package.tgz
    $ sudo chmod -R 777 /opt/spire

Create a link for **spire-server** and **spire-agent** so we can use them conveniently from any location.

    $ sudo ln -s /opt/spire/spire-server /usr/bin/spire-server
    $ sudo ln -s /opt/spire/spire-agent /usr/bin/spire-agent

## Configuration

Edit your server.conf so it looks for plugins at the right path:

    PluginDir = "/opt/spire/conf/server/plugin"

Edit your agent.conf so it looks for plugins and the trust bundle at the right path:

    PluginDir = "/opt/spire/conf/agent/plugin"
    TrustBundlePath = "/opt/spire/conf/agent/dummy_root_ca.crt"

Edit all your plugins configuration at **/opt/spire/conf/agent/plugin** and **/opt/spire/conf/server/plugin**. We have to add **/opt/spire/** at the beginning of each path to the pluginCmd config value.

    #server plugins
    pluginCmd = "/opt/spire/plugin/server/yourplugin"

    #agent plugins
    pluginCmd = "/opt/spire/plugin/agent/yourplugin"

For **upstream_ca_memory.conf** we have to modify key_file_path and cert_file_path:

    key_file_path = "/opt/spire/conf/server/dummy_upstream_ca.key"
    cert_file_path = "/opt/spire/conf/server/dummy_upstream_ca.crt"

## Running SPIRE with join token

Start your server.

    $ spire-server run \
        -config /opt/spire/conf/server/server.conf

In a different terminal create a jointoken.

    $ spire-server token generate -spiffeID spiffe://example.org/host
    # Token: aaaaaaaa-bbbb-cccc-dddd-111111111111

In the same terminal start the agent using the previously generated token.

    $ spire-agent run \
        -config /opt/spire/conf/agent/agent.conf \
        -joinToken {your previously generated token}

