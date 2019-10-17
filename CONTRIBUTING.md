# Contributor guidelines and Governance

Please see
[CONTRIBUTING](https://github.com/spiffe/spiffe/blob/master/CONTRIBUTING.md)
and
[GOVERNANCE](https://github.com/spiffe/spiffe/blob/master/GOVERNANCE.md)
from the SPIFFE project.

# Prerequisites

For basic development you will need:

* **Go** (https://golang.org/dl/)
* **Glide**, for managing third-party dependancies (https://github.com/Masterminds/glide)

For development that requires changes to the gRPC interfaces you will need:

* The protobuf compiler (https://github.com/google/protobuf)
* The protobuf documentation generator (https://github.com/pseudomuto/protoc-gen-doc)
* protoc-gen-go, protoc-gen-grpc-gateway and protoc-gen-swagger (`make utils`)


#  Building

It is assumed that this repository lives in $GOPATH/src/github.com/spiffe/spire on your local disk,
and that your GOPATH only contains one element.

Because of the use of Glide and the unusual layout of this repository a Makefile is provide for
common actions.

* `make all` - installs 3rd-party dependancies, build all binaries, and run all tests
* `make` - builds all binaries
* `make cmd/spire-agent` - builds one binary
* `make test` - runs all tests

**Other Makefile targets**

* `vendor` - installs 3rd-party dependencies using glide
* `race-test` - run `go test -race`
* `clean` - cleans `vendor` directory, glide cache
* `distclean` - removes caches in addition to `make clean`
* `utils` - installs gRPC related development utilities

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

Because the docker container shares $GOPATH you will not have to re-install the go dependencies
every time you run the container. NOTE: any binaries installed from within the container will be
located in $GOPATH/bin/linux_amd64 to avoid conflicts with the host OS (Packages are automatically
versioned by golang into `$GOPATH/pkg/<os>_<arch>`)

## CI

The script `build.sh` manages the CI build process, implementing several unique steps and sanity
checks. It is also used to bootstrap the Go environment in the Docker container.

* `setup` - download and install necessary build tools into the directory `.build-<os>-<arch>`
* `protobuf` - regenerate the gRPC pb.go and README.md files
* `protobuf_verify` - check that the checked-in generated code is up-to-date
* `distclean` - calls `make distclean` and removes the directory `.build-<os>-<arch>`
* `vendor` - calls `make vendor` and checks that the `glide.lock` file is up-to-date
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

`/plugin/{agent,server}/<name>/`

The implementation of each plugin and their support packages

`/proto/{agent,server,api,common}/<name>/`

gRPC .proto files, their generated .pb.go, and README_pb.md.

The protobuf package names should be `spire.{server,agent,api,common}.<name>` and the go package name
should be specified with `option go_package = "<name>";`

## Interfaces

Packages should be exported through interfaces. Interaction with packages must be done through these
interfaces

Interfaces should be defined in their own file, named (in lowercase) after the name of the
interface. eg. `foodata.go` implements `type FooData interface{}`

## Mocks

Unit tests should avoid mock tests as much as possible. When necessary we should inject mocked
object generated through mockgen

# Git hooks

We have checked in a pre-commit hook which enforces `go fmt` styling. Please install it
before sending a pull request. From the project root:

```
ln -s ../../.githooks/pre-commit .git/hooks/pre-commit
```
#### Reporting security vulnerabilities
If you've found a vulnerability or a potential vulnerability in SPIRE please let us know at security@spiffe.io. We'll send a confirmation email to acknowledge your report, and we'll send an additional email when we've identified the issue positively or negatively.  