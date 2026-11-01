#!/bin/bash
# Splits the integration test suites across NUM_RUNNERS shards and prints the
# suites assigned to shard THIS_RUNNER. Suites are assigned heaviest first to
# the least loaded shard, using the approximate durations listed in
# test/integration/suite-weights, so that every shard finishes at about the
# same time. Suites listed in IGNORE_SUITES are left out, since test.sh skips
# them and they would otherwise hold a slot on a shard for nothing.

set -e

if [ -z "$NUM_RUNNERS" ]; then
        echo "split.sh: NUM_RUNNERS environment variable must be set"
        exit 1
fi

if [ -z "$THIS_RUNNER" ]; then
        echo "split.sh: THIS_RUNNER environment variable must be set"
        exit 1
fi

WEIGHTS_FILE=test/integration/suite-weights
DEFAULT_WEIGHT=30

declare -A weight
while read -r name seconds; do
        if [[ -z "${name}" || "${name}" == \#* ]]; then
                continue
        fi
        weight["${name}"]="${seconds}"
done < "${WEIGHTS_FILE}"

# Heaviest first, with ties broken by name so the split is deterministic.
weighted_suites=$(
        for dir in test/integration/suites/*; do
                name=$(basename "${dir}")
                if [[ " ${IGNORE_SUITES} " == *" suites/${name} "* ]]; then
                        continue
                fi
                echo "${weight[${name}]:-${DEFAULT_WEIGHT}} ${name}"
        done | sort -k1,1nr -k2,2
)

declare -a load job_set
for ((runner=1; runner<=NUM_RUNNERS; runner++)); do
        load[runner]=0
done

while read -r seconds name; do
        lightest=1
        for ((runner=2; runner<=NUM_RUNNERS; runner++)); do
                if (( load[runner] < load[lightest] )); then
                        lightest=${runner}
                fi
        done
        load[lightest]=$(( load[lightest] + seconds ))
        job_set[lightest]+="suites/${name} "
done <<< "${weighted_suites}"

echo "${job_set[$THIS_RUNNER]}"
