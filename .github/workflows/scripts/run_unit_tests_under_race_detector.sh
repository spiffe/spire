#!/bin/bash

set -e

COVERPROFILE=
if [ -n "${COVERALLS_TOKEN}" ]; then
    COVERPROFILE=profile.cov
    go install github.com/mattn/goveralls@v0.0.7
fi

COVERPROFILE="${COVERPROFILE}" make race-test

if [ -n "${COVERALLS_TOKEN}" ]; then
    "$(go env GOPATH)"/bin/goveralls -coverprofile="${COVERPROFILE}" \
            -service=github
fi

# This ensures that running the tests didn't modify the source files, for
# example by generating test keys that should have been checked in with the PR.
make git-clean-check
