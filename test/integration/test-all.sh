#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "${DIR}"

for testdir in $(find . -type f -name setup); do
    ./test-one.sh "$(dirname ${testdir})"
done
