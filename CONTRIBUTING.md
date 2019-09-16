# Contributor guidelines and Governance

Please see
[CONTRIBUTING](https://github.com/spiffe/spiffe/blob/master/CONTRIBUTING.md)
and
[GOVERNANCE](https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md)
from the SPIFFE project.

# Prerequisites

For basic development you will need:

* **Go 1.11** or higher (https://golang.org/dl/)

For development that requires changes to the gRPC interfaces you will need:

* The protobuf compiler (https://github.com/google/protobuf)
* The protobuf documentation generator (https://github.com/pseudomuto/protoc-gen-doc)
* protoc-gen-go and protoc-gen-spireplugin (`make utils`)


#  Building

Since go modules are used, this repository can live in any folder on your local disk (it is not required to be in GOPATH).

A Makefile is provided for common actions.

* `make all` - installs 3rd-party dependencies, build all binaries, and run all tests
* `make` - builds all binaries
* `make cmd/spire-agent` - builds one binary
* `make test` - runs all tests

**Other Makefile targets**

* `vendor` - Make vendored copy of dependencies using go mod
* `race-test` - run `go test -race`
* `clean` - cleans `vendor` directory
* `distclean` - removes caches in addition to `make clean`
* `utils` - installs gRPC related development utilities
* `protobuf` - regenerates the gRPC pb.go and README_pb.md files
* `protobuf_verify` - checks that the checked-in generated code is up-to-date
* `help` - shows makefile targets and description

## Development in Docker

You can either build Spire on your host or in a Ubuntu docker container. In both cases you will use
the same Makefile commands.

To run in a docker container set the environment variable `SPIRE_DEV_HOST` to `docker` like so:

```
$ export SPIRE_DEV_HOST=docker
```

To set up the build container and run bash within it:

```
$ make container
$ make cmd
```

Because the docker container shares `$GOPATH/pkg/mod` you will not have to re-install the go dependencies every time you run the container.

## CI

The script `build.sh` manages the CI build process, implementing several unique steps and sanity
checks. It is also used to bootstrap the Go environment in the Docker container.

* `setup` - download and install necessary build tools into the directory `.build-<os>-<arch>`
* `protobuf` - calls `make protobuf` and regenerates the gRPC pb.go and README_pb.md files
* `protobuf_verify` - calls `make protobuf_verify` and checks that the checked-in generated code is up-to-date
* `distclean` - calls `make distclean` and removes the directory `.build-<os>-<arch>`
* `artifact` - generate a `.tgz` containing all of the SPIFFE binaries
* `test` - when called from within a Travis-CI build, runs coverage tests in addition to the
  regular tests
* `utils` - calls `make utils` and installs additional packages for the CI build
* `eval $(build.sh env)` - configure GOPATH, GOROOT and PATH to use the private build tool directory


# Conventions

In addition to the conventions covered in the SPIFFE project's
[CONTRIBUTING](https://github.com/spiffe/spiffe/blob/master/CONTRIBUTING.md), the following
conventions apply to the SPIRE repository:

## Directory layout

`/cmd/{spire-server,spire-agent}/`

The CLI implementations of the agent and server commands

`/pkg/{agent,server}/`

The main logic of the agent and server processes and their support packages

`/pkg/common/`

Common functionality for agent, server, and plugins

`/pkg/{agent,server}/plugin/<name>/`

The implementation of each plugin and their support packages

`/proto/spire/{agent,server,api,common}/<name>/`

gRPC .proto files, their generated .pb.go, and README_pb.md.

The protobuf package names should be `spire.{server,agent,api,common}.<name>` and the go package name
should be specified with `option go_package = "<name>";`

## Interfaces

Packages should be exported through interfaces. Interaction with packages must be done through these
interfaces

Interfaces should be defined in their own file, named (in lowercase) after the name of the
interface. eg. `foodata.go` implements `type FooData interface{}`

## Metrics

As much as possible, label names should be constants defined in the `telemetry` package.

Labels added to metrics must be singular; that is, the value of a metrics label must not be an
array or slice, and a label of some name must only be added once. Failure to follow this will
make metrics less usable for non-tagging metrics libraries such as `statsd`.
As counter examples, DO NOT do the following:
```
[]telemetry.Label{
  {Name: "someName", "val1"},
  {Name: "someName", "val2"},
}
```
```
var callCounter telemetry.CallCounter
...
callCounter.AddLabel("someName", "val1")
...
callCounter.AddLabel("someName", "val2")
```

## Logs and Errors

Errors should start with lower case, and logged messages should follow standard casing.

Log messages should make use of logging fields to convey additional information, rather than
using string formatting which increases the cardinality of messages for log watchers to
look for and hinders aggregation.

## Mocks

Unit tests should avoid mock tests as much as possible. When necessary we should inject mocked
object generated through mockgen

# Git hooks

We have checked in a pre-commit hook which enforces `go fmt` styling. Please install it
before sending a pull request. From the project root:

```
ln -s .githooks/pre-commit .git/hooks/pre-commit
```
