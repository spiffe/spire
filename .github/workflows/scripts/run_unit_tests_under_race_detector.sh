#!/bin/bash

set -e

COVERPROFILE=
if [ -n "${COVERALLS_TOKEN}" ]; then
    COVERPROFILE=profile.cov
    go get github.com/mattn/goveralls@v0.0.7
fi

COVERPROFILE="${COVERPROFILE}" \
    SKIP_FLAKY_TESTS_UNDER_RACE_CONDITION=1 \
    GOVERBOSE=1 \
    make race-test

if [ -n "${COVERALLS_TOKEN}" ]; then
    "$(go env GOPATH)"/bin/goveralls -coverprofile="${COVERPROFILE}" \
            -service=github
fi
