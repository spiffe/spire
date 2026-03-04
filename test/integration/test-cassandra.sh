#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ORIGDIR=${DIR}

cd "${DIR}" || fail-now "Unable to change to script directory"

. ./common

cd "${DIR}"/setup/cassandra-multinode && source ./setup || fail-now "Cassandra multinode setup failed"
cd "${ORIGDIR}" || fail-now "Unable to change back to script directory"
SUITES="${ORIGDIR}/cassandra-suites/*"

ignore_suites=(${IGNORE_SUITES})
echo "Testing $SUITES"

# These "suites" either setup their own Cassandra cluster or are not tests.
always_skip=("datastore-cassandra" "datastore-cassandra-focus" "datastore-cassandra-multinode" "datastore-cassandra-multinode-multidc" "test-suite.md")

failed=()
for suite in $SUITES; do
    if [[ " ${ignore_suites[*]} " =~ " ${suite} " ]]; then
        log-warn "Ignoring ${suite} suite..."
    else
        for i in "${always_skip[@]}"; do
            if [ "$(basename "${suite}")" == "${i}" ]; then
                continue 2 # skip to next suite
            fi
        done
        ./test-one-cassandra.sh "${suite}"
        status=$?
        if [ ${status} -ne 0 ]; then
            echo "test-one-cassandra.sh returned status=${status}"
            failed+=( "$(basename "${suite}")" )
        fi
    fi
done
cd "${ORIGDIR}"/setup/cassandra-multinode && source ./teardown || fail-now "Cassandra teardown failed"

[ ${#failed[@]} -eq 0 ] || fail-now "The following tests failed: ${failed[*]}"
