#!/bin/bash

set -e

if [ -z "$NUM_RUNNERS" ]; then
        echo "split.sh: NUM_RUNNERS environment variable must be set"
        exit 1
fi

if [ -z "$THIS_RUNNER" ]; then
        echo "split.sh: THIS_RUNNER environment variable must be set"
        exit 1
fi

declare -a job_set
current_runner=1
for FILE in test/integration/suites/k8s*; do
        job_set[$current_runner]+="${FILE##test/integration/} "

        ((current_runner++))
        if [ "$current_runner" -gt "$NUM_RUNNERS" ]; then
                current_runner=1
        fi
done

echo "${job_set[$THIS_RUNNER]}"
