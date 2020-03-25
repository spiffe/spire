#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

GOBINPATH=$(cd "${REPODIR}"; make go-bin-path)

PATH="${GOBINPATH}" go run "${DIR}/gencerts.go" "$@"
