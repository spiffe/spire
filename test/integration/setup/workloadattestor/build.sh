#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/$1"

cd "${DIR}" && CGO_ENABLED=0 GOOS=linux go build -o $2
