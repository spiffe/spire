[![Build Status](https://travis-ci.com/spiffe/sri.svg?token=pXzs6KRAUrxbEXnwHsPs&branch=master)](https://travis-ci.com/spiffe/sri)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/sri/badge.svg?t=SrV7ye)](https://coveralls.io/github/spiffe/sri)

# SPIFFE Reference Implementation (SRI)

The SPIFFE Reference Implementation provides a toolchain that defines a central registry of
SPIFFE IDs (the Control Plane), and a Node Agent that can be run adjacent to a workload and
exposes a local Workload API.

## Building the SRI

The script `build.sh` manages the build process and can be used for development. It expects
this repo to be present at and to be run from `$GOPATH/src/github.com/spiffe/sri`. It has
been tested on Linux only.

`build.sh setup` will download and install necessary dependencies (including golang)
into the directory `.build/`.

`deps` processes the `glide.lock` file

`protobuf` will regenerate the gRPC pb.go and README.md files 

`binaries` will build the main binary and the plugins

`test` will run the tests

`clean` remove built binaries and 

`distclean` remove built binaries as well as the `.build` directory

`build.sh` with no options will list available functions

`eval $(build.sh env)` will configure GOPATH, GOROOT and PATH for development outside
of `build.sh`

## Developing the SRI

The above-referenced build scripts may be used natively under Linux. For your convenience,
a Dockerfile and accompanying Makefile will get you to a suitable Linux shell.

```
$ make build
$ make launch
root@65a22fa2d89f:~/go/src/github.com/spiffe/sri# ./build.sh setup
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

