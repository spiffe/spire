#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "${DIR}/.."

docker compose up -d cassandra-5

MAXCHECKS=40
CHECKINTERVAL=3
READY=
for ((i=1;i<=MAXCHECKS;i++)); do
    echo "waiting for cassandra-5 ($i of $MAXCHECKS max)..."
    if docker compose exec -T "cassandra-5" nodetool status >/dev/null; then
        READY=1
        break
    fi
    sleep "${CHECKINTERVAL}"
done

if [ -z ${READY} ]; then
    echo "timed out waiting for cassandra-5 to be ready"
    exit 1
fi

exit 0
