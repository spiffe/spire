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

* `make` - builds all binaries
* `make all` - build all binaries, and run all tests
* `make bin/spire-server` - builds SPIRE server
* `make bin/spire-agent` - builds SPIRE agent
* `make images` - builds SPIRE docker images
* `make test` - runs unit tests

See `make help` for other targets

The Makefile takes care of installing the required toolchain as needed. The
toolchain and other build related files are cached under the `.build` folder
(ignored by git).

## Development in Docker

You can either build SPIRE on your host or in a Ubuntu docker container. In
both cases you will use the same Makefile commands.

To build SPIRE within a container, first build the development image:

```
$ make dev-image
```

Then launch a shell inside of development container:

```
$ make dev-shell
```

Because the docker container shares the `.build` cache and `$GOPATH/pkg/mod`
you will not have to re-install the toolchain or go dependencies every time you
run the container.

# Conventions

In addition to the conventions covered in the SPIFFE project's
[CONTRIBUTING](https://github.com/spiffe/spiffe/blob/master/CONTRIBUTING.md), the following
conventions apply to the SPIRE repository:

## SQL Plugin Changes

Datastore changes must be present in at least one full minor release cycle prior to introducing code changes that depend on them.

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

As much as possible, label names should be constants defined in the `telemetry` package. Additionally,
specific metrics should be centrally defined in the `telemetry` package or its subpackages. Functions
desiring metrics should delegate counter, gauge, timer, etc. creation to such packages.

Labels added to metrics must be singular only; that is:

- the value of a metrics label must not be an array or slice, and a label of some name must only be added
once. Failure to follow this will make metrics less usable for non-tagging metrics libraries such as `statsd`.
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

- the existence of a metrics label is constant for all instances of a given metric. For some given metric A with
label X, label X must appear in every instance of metric A rather than conditionally. Failure to follow this will
make metrics less usable for non-tagging metrics libraries such as `statsd`, and potentially break aggregation for
tagging metrics libraries.
As a counter example, DO NOT do the following:
```
var callCounter telemetry.CallCounter
...
if caller != "" {
  callCounter.AddLabel("caller_id", caller)
}
...
if x > 5000 {
  callCounter.AddLabel("big_load", "true")
}
```
Instead, the following would be more acceptable:
```
var callCounter telemetry.CallCounter
...
if caller != "" {
  callCounter.AddLabel("caller_id", caller)
} else {
  callCounter.AddLabel("caller_id", "someDefault")
}
...
if x > 5000 {
  callCounter.AddLabel("big_load", "true")
} else {
  callCounter.AddLabel("big_load", "false")
}
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
# Reporting security vulnerabilities
If you've found a vulnerability or a potential vulnerability in SPIRE please let us know at security@spiffe.io. We'll send a confirmation email to acknowledge your report, and we'll send an additional email when we've identified the issue positively or negatively.
