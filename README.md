[![CircleCI](https://circleci.com/gh/spiffe/control-plane.svg?style=svg&circle-token=0426fa60a9cc237f4065ed4670d3b9b23ae30be8)](https://circleci.com/gh/spiffe/control-plane)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/control-plane/badge.svg?branch=dave-build3&t=PpzC6u)](https://coveralls.io/github/spiffe/control-plane?branch=dave-build3)

# control-plane

Build Environment
------------
The script `build.sh` manages the build process and can be used for development. It expects
this repo to be present at and to be run from `$GOPATH/src/github.com/spiffe/control-plane`.

`build.sh setup` will download and install necessary dependancies (including golang)
into the directory `.build/`

`deps` processes the `glide.lock` file

`protobuf` will regenerate the gRPC pb.go and README.md files 

`binaries` will build the main binary and the plugins

`test` will run the tests

`clean` remove built binaries and 

`distclean` remove built binaries as well as the `.build` directory

`build.sh` with no options will list available functions

`eval $(build.sh env)` will configure GOPATH, GOROOT and PATH for development outside
of `build.sh`

Prerequisites when not using build.sh
-------------

* The Go compiler and tools from https://golang.org/
* protoc from https://github.com/google/protobuf
* protoc-gen-go from https://github.com/golang/protobuf

Constraints
-----------



Documentation
-------------


Status
------



FAQ
---
