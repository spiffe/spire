![SPIRE Logo](https://github.com/spiffe/spire/blob/master/doc/images/spire_logo.png?raw=true)

![Build Status](https://travis-ci.org/spiffe/spire.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/spire/badge.svg?branch=master)](https://coveralls.io/github/spiffe/spire?branch=master)

SPIRE (the [SPIFFE](https://github.com/spiffe/spiffe) Runtime Environment) is a tool-chain for establishing trust between software systems across a wide variety of hosting platforms. Concretely, SPIRE exposes the [SPIFFE Workload API](https://github.com/spiffe/spire/blob/master/proto/api/workload/workload.proto), which can attest running software systems and issue [SPIFFE IDs](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md) and [SVID](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md)s to them. This in turn allows two workloads to establish trust between each other, for example by establishing an mTLS connection or by signing and verifying a JWT token.

- [Learn about SPIRE](#learn-about-spire)
- [Get SPIRE](#get-spire)
- [Getting started](#getting-started)
    - [Installing SPIRE Server and Agent](#installing-spire-server-and-agent)
    - [Configure the Server](#configure-the-server)
    - [Configure the Agent](#configure-the-agent)
    - [Joining to the SPIRE server with a join token](#joining-to-the-spire-server-with-a-join-token)
    - [Workload Registration](#workload-registration)
    - [Workload SVID Retrieval](#workload-attestation)
- [Community](#community)

> Please note that the SPIRE project is pre-alpha. It is under heavy development, and is NOT suitable for production use. See the [open issues](https://github.com/spiffe/spire/issues) or drop by our [Slack channel](https://slack.spiffe.io/) for more information.

# Get SPIRE

Pre-built releases can be found at [https://github.com/spiffe/spire/releases](https://github.com/spiffe/spire/releases). These releases contain both server and agent binaries plus the officially supported plugins.

Alternatively you can [build SPIRE from source](/CONTRIBUTING.md)

# Getting started

Before trying out SPIRE, we recommend becoming familiar with it's [architecture](https://spiffe.io/spire/) and design goals. 

To provide a minimal example of how SPIRE can be used, we are going to set up an [SPIRE Server](/doc/spire_server.md) and [SPIRE Agent](/doc/spire_agent.md). We will use them to issue identities to a workload identified by being run under a specified unix user ID.

For simplicity we will install both [SPIRE Server](/doc/spire_server.md) and [SPIRE Agent](/doc/spire_agent.md) on the same machine. In an actual deployment, these would typically run on different machines.

> **Note**:
> This getting started guide assumes that you are running **Ubuntu 16.04**.

## Installing SPIRE Server and Agent

Get the latest tarball from [here](https://github.com/spiffe/spire/releases) and then extract it into **/opt/spire** with the next commands:

    $ sudo tar zvxf {your_downloaded_tarball.tar.gz}
    $ sudo cp -r spire-0.2/. /opt/spire/
    # the name spire-0.2 might change depending on the tarball version downloaded
    $ sudo chmod -R 777 /opt/spire/

Add **spire-server** and **spire-agent** to our $PATH for convenience:

    $ sudo ln -s /opt/spire/spire-server /usr/bin/spire-server
    $ sudo ln -s /opt/spire/spire-agent /usr/bin/spire-agent

## Configure the SPIRE Server

After putting the agent and server binaries at the proper location we have to configure them. The SPIRE Server relies on plugins for much of it's functionality, so we must make sure the agent and server can find the relevant plugins. For more information on the SPIRE se

Edit **/opt/spire/conf/server/server.conf** so it looks for plugins at the right path:

    PluginDir = "/opt/spire/conf/server/plugin"

Individual plugins can be configured at **/opt/spire/conf/agent/plugin** and **/opt/spire/conf/server/plugin**. Each plugin configuration must be set up so the SPIRE server can find the appropriate plugin binaries.

    pluginCmd = "/opt/spire/plugin/server/{plugin_binary}"

Every SVID issued by a SPIRE installation is issued from a common trust root. SPIRE provides a pluggable mechanism for how this trust root can be retrieved, by default it will use a key distributed on disk. The release includes a dummy CA key that we can use for testing purposes, but the default plugin (the `upstream_ca_memory` plugin) must be configured to find it.

For **upstream_ca_memory.conf** we have to modify key_file_path and cert_file_path:

    key_file_path = "/opt/spire/conf/server/dummy_upstream_ca.key"
    cert_file_path = "/opt/spire/conf/server/dummy_upstream_ca.crt"

The [SPIRE Server](/doc/spire_server.md) reference guide covers in more detail the specific configuration options and plugins available.

## Configure the SPIRE Agent

The SPIRE Agent also relies on plugins, and must be configured to find them. When connecting back to the SPIRE Server, the SPIRE agent uses an X.509 certificate to verify the connection. SPIRE releases come with a "dummy" certificate in the client and server. For a production implementation, a separate key would be generated for the server and certificate to be bundled with the agent.

Edit **/opt/spire/conf/agent/agent.conf** so it looks for plugins and the trust bundle at the right path:

    PluginDir = "/opt/spire/conf/agent/plugin"
    TrustBundlePath = "/opt/spire/conf/agent/dummy_root_ca.crt"

As with the server, individual plugins can be configured at **/opt/spire/conf/agent/plugin**. Ensure each plugin configuration file is configured with the path to the appropriate plugin binary:

    pluginCmd = "/opt/spire/plugin/agent/{plugin_binary}"

The [SPIRE Agent](/doc/spire_agent.md) reference guide covers in more detail the specific configuration options and plugins available.

## Joining to the SPIRE server with a join token

We will start a server and join an agent to it using the join token attestation method. _A join token is a manually generated single-use token that can be used to authenticate a connection. In more sophisticated implementations, SPIRE can be configured to use platform-specific mechanisms to authenticate an Agent to a Server._

Start your server.

    $ spire-server run \
        -config /opt/spire/conf/server/server.conf

In a different terminal generate a one time Join Token via **spire-server token generate** sub commmand. Use the **-spiffeID** option to associate the Join Token with **spiffe://example.org/host** SPIFFE ID.

    $ spire-server token generate \
        -spiffeID spiffe://example.org/host
    # Token: aaaaaaaa-bbbb-cccc-dddd-111111111111

The Join Token will be used for node attestation and the associated [SPIFFE ID](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md#2-spiffe-identity) will be used to generate the [SVID](https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md) of the attested node.

The default ttl of the Join Token is 600 seconds. We can overwrite the default value through **-ttl** option.

In the same terminal start the agent using the previously generated token so we can join it with the server.

    $ spire-agent run \
        -config /opt/spire/conf/agent/agent.conf \
        -joinToken {your previously generated token}

## Workload Registration

We need to register the workload in the server so we can define under which attestation policy we are going to grant an identity to the workload.
Since we are going to register it using an uid unix selector that will be mapped to a target [SPIFFE ID](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md#2-spiffe-identity), we first need to create a new user that we will call **workload**.

In a new terminal, create the user:

    $ sudo useradd workload

Get the id so we can use it in the next step.

    $ id -u workload

Call the registration API with *spire-server register* providing the workload user id.

    $ spire-server register \
        -parentID spiffe://example.org/host \
        -spiffeID spiffe://example.org/host/workload \
        -selector unix:uid:{workload user id from previous step}

At this point, the registration API has been called and the target workload has been registered with the SPIRE Server. We can now call the workload API using a command line program to request the workload [SVID](https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md) from the SPIRE Agent.

## Workload SVID Retrieval

We will simulate the workload API interaction and retrieve the workload [SVID](https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md) bundle by running the `api` subcommand in the agent. Run the command as the user **_workload_** that we created in the previous step.

> **Note**: If you are running on Vagrant you will need to run `sudo -i` first.

    $ su -c "spire-agent api fetch" workload
    # SPIFFE ID:         spiffe://example.org/host/workload
    # SVID Valid After:  yyyy-MM-dd hh:mm:ss +0000 UTC
    # SVID Valid Until:  yyyy-MM-dd hh:mm:ss +0000 UTC
    # CA #1 Valid After: yyyy-MM-dd hh:mm:ss +0000 UTC
    # CA #1 Valid Until: yyyy-MM-dd hh:mm:ss +0000 UTC

Optionally, you may write the SVID and key to disk with `-write` in order to examine them in detail with openssl.

    $ su -c "spire-agent api fetch -write /opt/spire/" workload
    $ openssl x509 -in /opt/spire/svid.0.pem -text -noout
    # Certificate:
    #     Data:
    #         Version: 3 (0x2)
    #         Serial Number: 4 (0x4)
    #     Signature Algorithm: sha256WithRSAEncryption
    #         Issuer: C=US, O=SPIFFE
    #         Validity
    #             Not Before: Dec  1 15:30:54 2017 GMT
    #             Not After : Dec  1 16:31:04 2017 GMT
    #         Subject: C=US, O=SPIRE
    #         Subject Public Key Info:
    #             Public Key Algorithm: id-ecPublicKey
    #                 Public-Key: (521 bit)
    #                 pub:
    #                     04:01:fd:33:24:81:65:b9:5d:7e:0b:3c:2d:11:06:
    #                     aa:a4:32:89:20:bb:df:33:15:7d:33:55:13:13:cf:
    #                     e2:39:c7:fa:ae:2d:ca:5c:d1:45:a1:0b:90:63:16:
    #                     6e:b8:aa:e9:21:36:30:af:95:32:35:52:fb:11:a5:
    #                     3a:f0:c0:72:8f:fa:63:01:95:ec:d9:99:17:8c:9d:
    #                     ca:ff:c4:a7:20:62:8f:88:29:19:32:65:79:1c:b8:
    #                     88:5d:63:80:f2:42:65:4b:9e:26:d0:04:5a:58:98:
    #                     a3:82:41:b0:ab:92:c9:38:71:00:50:c5:6d:3f:ab:
    #                     46:47:53:92:eb:be:42:55:44:1a:22:0b:ef
    #                 ASN1 OID: secp521r1
    #                 NIST CURVE: P-521
    #         X509v3 extensions:
    #             X509v3 Key Usage: critical
    #                 Digital Signature, Key Encipherment, Key Agreement
    #             X509v3 Extended Key Usage:
    #                 TLS Web Server Authentication, TLS Web Client Authentication
    #             X509v3 Basic Constraints: critical
    #                 CA:FALSE
    #             X509v3 Subject Alternative Name:
    #                 URI:spiffe://example.org/host/workload
    #     Signature Algorithm: sha256WithRSAEncryption
    #          98:5e:33:14:ff:8e:77:40:1d:da:68:13:34:65:66:29:d0:f3:
    #          fa:c7:e5:45:58:4c:13:49:ad:47:4b:8e:ff:ad:e5:72:ca:7d:
    #          45:ac:c8:88:3d:66:63:3f:f7:56:0e:34:df:9c:51:9f:7d:b9:
    #          99:6f:a2:c8:78:bf:08:8c:02:17:ec:42:b8:5c:a9:e6:58:5a:
    #          cb:0f:16:3f:85:8a:08:20:2c:23:61:e3:89:48:f1:f0:bc:73:
    #          2a:c0:9c:29:0e:ed:d8:2f:53:2c:82:67:70:6b:14:a1:eb:43:
    #          1a:c5:04:0d:82:5b:f4:aa:3b:c5:37:db:22:17:97:ff:dc:d8:
    #          01:27:44:29:18:1f:76:a3:9e:6a:50:31:5a:65:09:91:d7:8a:
    #          79:03:0c:e9:22:f9:6c:15:02:db:a9:e2:fc:73:15:82:3a:0e:
    #          dd:4f:e5:04:b6:84:31:71:0d:ee:c5:b5:5a:21:d0:a9:8d:ec:
    #          8c:4d:95:f2:43:b3:e9:ae:81:db:56:37:a2:74:23:69:05:1a:
    #          2c:c8:11:09:40:18:67:6f:77:ff:57:ea:73:cd:49:9d:ba:6c:
    #          85:70:d7:5c:a5:ba:46:0e:86:a2:c1:1d:27:f2:7a:2d:c1:4b:
    #          16:87:b2:97:2f:98:ed:80:2a:5e:62:f4:7f:87:82:ff:67:96:
    #          e6:2e:fa:a1

# Community

The SPIFFE community, and [Scytale](https://scytale.io) in particular, maintain the SPIRE project.
Information on the various SIGs and relevant standards can be found in
https://github.com/spiffe/spiffe.

The SPIFFE and SPIRE governance policies are detailed in
[GOVERNANCE](https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md)
