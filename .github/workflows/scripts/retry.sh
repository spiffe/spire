#!/usr/bin/env bash

# retry runs the given command, retrying with exponential backoff if it fails.
# It is intended to harden CI steps against transient registry/network errors
# (e.g. Docker Hub image pull timeouts during a `docker buildx build`) that
# would otherwise cause spurious build failures.

set -u

attempts=5
delay=5
max_delay=60
attempt=1

if [ "$#" -eq 0 ]; then
    echo "retry: no command given" >&2
    exit 2
fi

while true; do
    if "$@"; then
        exit 0
    fi
    if [ "${attempt}" -ge "${attempts}" ]; then
        echo "retry: command failed after ${attempt} attempt(s): $*" >&2
        exit 1
    fi
    echo "retry: command failed (attempt ${attempt}/${attempts}), retrying in ${delay}s: $*" >&2
    sleep "${delay}"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
    if [ "${delay}" -gt "${max_delay}" ]; then
        delay="${max_delay}"
    fi
done
