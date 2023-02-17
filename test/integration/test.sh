#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "${DIR}" || fail-now "Unable to change to script directory"

. ./common

if [[ -z "${SUITES}" ]]; then
   SUITES=suites/*
fi

if [[ -n $1 ]]; then
        SUITES=$@
fi

ignore_suites=(${IGNORE_SUITES})
echo "Testing $SUITES"

failed=()
for suite in $SUITES; do
    if [[ " ${ignore_suites[*]} " =~ " ${suite} " ]]; then
        log-warn "Ignoring ${suite} suite..."
    elif ! ./test-one.sh "${suite}"; then
        echo "STATUS=$?"
        failed+=( "$(basename "${suite}")" )
    fi
done

[ ${#failed[@]} -eq 0 ] || fail-now "The following tests failed: ${failed[*]}"
