#!/bin/bash

set -e

REPODIR=$(git rev-parse --show-toplevel)

COVERPROFILE=
if [ -n "${COVERALLS_TOKEN}" ]; then
    COVERPROFILE=profile.cov
    go get github.com/mattn/goveralls@v0.0.4
fi

make -C "${REPODIR}" COVERPROFILE="${COVERPROFILE}" test

if [ -n "${COVERALLS_TOKEN}" ]; then
    "$(go env GOPATH)"/bin/goveralls -covermode race -service=travis-ci
fi
