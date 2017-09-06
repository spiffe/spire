[![Build Status](https://travis-ci.com/spiffe/spire.svg?token=pXzs6KRAUrxbEXnwHsPs&branch=master)](https://travis-ci.com/spiffe/spire)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/spire/badge.svg?t=SrV7ye)](https://coveralls.io/github/spiffe/spire)

# SPIFFE Runtime Environment (SPIRE)

The SPIFFE Reference Implementation provides a toolchain that defines a central registry of
SPIFFE IDs (the Server), and a Node Agent that can be run adjacent to a workload and
exposes a local Workload API.

## Installing SPIRE

`go get github.com/spiffe/spire/...` will fetch and build all of SPIRE and its
dependencies and install them in $GOPATH/bin

## Configuring SPIRE

All SPIRE component configuration files are in the Hashicorp [HCL](https://github.com/hashicorp/hcl)
format. HCL is less verbose than JSON and permits comments. And unlike YAML, it does not suffer
from the ambiguity of when to use a : versus a -.

The SPIRE server and agent require a configuration file that includes:

* `trustDomain` - the SPIFFE trust domain
* `logFile` - the pathname to the logfile. This logfile is overwritten on every server start
* `logLevel` - the verbosity level of the logs, which will default to NONE if not set to
  DEBUG, INFO, WARN, or ERROR
* The local TCP port that each plugin is listening on

An example server configuration:
```
logFile = "spire-server.log"
logLevel = "DEBUG"
nodeAPIGRPCPort = "8086"
registrationAPIGRPCPort ="8086"
nodeAPIHTTPPort = "8086"
registrationAPIHTTPPort ="8086"
trustDomain = "spiffe://"
```

Each plugin also requires a configuration file that is read by the server
or agent process in addition to the plugin itself. The configuration includes:

* `pluginName` - the plugin name, which must match the string defined in plugin serverConfig
* `pluginType` - plugin type, which must match the plugin name presented during the handshake
* `pluginCmd` - path to the plugin binary
* `pluginChecksum` - plugin checksum, if using
* `enabled` - whether to load the plugin or not
* `pluginData` - an arbitrary dictionary of additional configuration for the plugin

Example configuration for the token-based Node Attester:

```
pluginName = "join_token"
pluginType = "NodeAttestor"
pluginCmd = "../../plugin/agent/nodeattestor-jointoken/nodeattestor-jointoken"
pluginChecksum = ""
enabled = true
pluginData {
  join_token = "NOT-A-SECRET"
}
```

## Starting the server and agent

The server and agent support two environment variables to set the location of their configuration:

* `SPIRE_SERVER_CONFIG` - path to the .hcl file containing server configuration.
  Defaults to `$PWD/.conf/default_server_config.hcl`
* `SPIRE_AGENT_CONFIG_PATH` - path to the .hcl file containing agent configuration.
  Defaults to `$PWD/.conf/default_agent_config.hcl`

Both server and agent support:

* `SPIRE_PLUGIN_CONFIG_DIR` - path to the directory containing per-plugin configuration files.
  This directory must _only_ contain plugin configurations. Defaults to
  `$PWD/../../plugin/server/.conf/` and `$PWD/../../plugin/agent/.conf`

To start the agent:

```
SPIRE_PLUGIN_CONFIG_DIR=/etc/spire/pluginconf SPIRE_AGENT_CONFIG_PATH=/etc/spire/default_agent_config.hcl spire-agent start
```

The agent will run silently in the foreground, logging status to its logfile.


## Building SPIRE for development

The script `build.sh` manages the build process and can be used for development. It expects
this repo to be present at and to be run from `$GOPATH/src/github.com/spiffe/spire`. It has
been tested on Linux only.

* `build.sh setup` will download and install necessary dependencies (including golang)
into the directory `.build/`.
* `deps` processes the `glide.lock` file
* `protobuf` will regenerate the gRPC pb.go and README.md files
* `binaries` will build the main binary and the plugins
* `test` will run the tests
* `clean` remove built binaries and
* `distclean` remove built binaries as well as the `.build` directory
* `build.sh` with no options will list available functions
* `eval $(build.sh env)` will configure GOPATH, GOROOT and PATH for development outside
of `build.sh`

## Developing SPIRE

The above-referenced build scripts may be used natively under Linux. For your convenience,
a Dockerfile and accompanying Makefile will get you to a suitable Linux shell.

```
$ make build
$ make launch
root@65a22fa2d89f:~/go/src/github.com/spiffe/spire# ./build.sh setup
...
```

### Prerequisites

* Linux or Docker

If not using Docker, the following "non-standard" utilities are also required:

* `curl`
* `git`
* `unzip`

### Git hooks

We have checked in a pre-commit hook which enforces `go fmt` styling. Please install it
before sending a pull request. From the project root:

```
ln -s ../../.githooks/pre-commit .git/hooks/pre-commit
```
