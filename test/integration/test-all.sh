#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "${DIR}" || fail-now "Unable to change to script directory"

. ./common

failed=()
for suite in suites/*; do
    if ! ./test-one.sh "${suite}"; then
        failed+=( "$(basename ${suite})" )
    fi
done

[ ${#failed[@]} -eq 0 ] || fail-now "The following tests failed: ${failed[*]}"
