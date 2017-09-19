[![Build Status](https://travis-ci.com/spiffe/spire.svg?token=pXzs6KRAUrxbEXnwHsPs&branch=master)](https://travis-ci.com/spiffe/spire)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/spire/badge.svg?branch=master&t=GWBRCP)](https://coveralls.io/github/spiffe/spire?branch=master)

![SPIRE Logo](/doc/spire_logo.png)

SPIRE (the SPIFFE Reference Implementation) provides a toolchain that defines a central registry of
SPIFFE IDs (the Server), and a Node Agent that can be run adjacent to a workload and
exposes a local Workload API.

## Installing SPIRE

`go get github.com/spiffe/spire/...` will fetch and build all of SPIRE and its
dependencies and install them in $GOPATH/bin

## Configuring SPIRE

See the [server README](/cmd/spire-server/README.md) and the [agent
README](/cmd/spire-agent/README.md)

## Building SPIRE

### Prerequisites

For basic development you will need:

* **Go** (https://golang.org/dl/)
* **Glide**, for managing third-party dependancies (https://github.com/Masterminds/glide)

For development that requires changes to the gRPC interfaces you will need:

* The protobuf compiler (https://github.com/google/protobuf)
* The protobuf documentation generator (https://github.com/pseudomuto/protoc-gen-doc)
* protoc-gen-go, protoc-gen-grpc-gateway and protoc-gen-swagger (`make utils`)


###  Building

It is assumed that this repository lives in $GOPATH/src/github.com/spiffe/spire on your local disk,
and that your GOPATH only contains one element.

Because of the use of Glide and the unusual layout of this repository a Makefile is provide for
common actions.

* `make all` - installs 3rd-party dependancies, build all binaries, and run all tests
* `make build` - only builds binaries
* `make cmd/spire-agent` - builds one binary
* `make test` - runs all tests

**Other Makefile targets**

* `vendor` - installs 3rd-party dependencies using glide
* `race-test` - run `go test -race`
* `clean` - cleans `vendor` directory, glide cache
* `distclean` - removes caches in addition to `make clean`
* `utils` - installs gRPC related development utilities
* `container` - builds the docker image
* `cmd` - runs /bin/bash in the container

### Development in Docker

You can either build Spire on your host or in a Ubuntu docker container. In both cases you will use
the same Makefile commands.

To run in a docker container set the environment variable `SPIRE_DEV_HOST` to `docker` like so:

```
$: export SPIRE_DEV_HOST=docker
```

To set up the build container:

```
$: make container
```

This will download and build a docker image from the `Dockerfile` in this directory. Because the
docker container shares $GOPATH you will not have to re-install the go dependencies every time you
run the container. NOTE: any binaries installed from within the container will be located in
$GOPATH/bin/linux_amd64 to avoid conflicts with the host OS. Packages are automatically versioned by
golang into $GOPATH/pkg/\<os\>_\<arch\>

### CI

The script `build.sh` manages the CI build process, implementing several unique steps and sanity
checks. It is also used to bootstrap the Docker container.

* `setup` - download and install necessary build tools into the directory *.build-\<os\>-\<arch\>*
* `protobuf` - regenerate the gRPC pb.go and README.md files
* `protobuf_verify` - check that the checked-in generated code is up-to-date
* `distclean` - calls `make distclean` and removes CI-related caches
* `eval $(build.sh env)` - configure GOPATH, GOROOT and PATH to use the private build tool directory


### Git hooks

We have checked in a pre-commit hook which enforces `go fmt` styling. Please install it
before sending a pull request. From the project root:

```
ln -s ../../.githooks/pre-commit .git/hooks/pre-commit
```
