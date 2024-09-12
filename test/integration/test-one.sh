#!/bin/bash

ROOTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COMMON="${ROOTDIR}/common"

# shellcheck source=./common
source "${COMMON}"

[ -n "$1" ] || fail-now "must pass the test suite directory as the first argument"
[ -d "$1" ] || fail-now "$1 does not exist or is not a directory"

TESTDIR="$( cd "$1" && pwd )"
TESTNAME="$(basename "${TESTDIR}")"

# Capture the top level directory of the repository
REPODIR=$(git rev-parse --show-toplevel)

# Set and export the PATH to one that includes a go binary installed by the
# Makefile, if necessary.
PATH=$(cd "${REPODIR}" || exit; make go-bin-path)
export PATH

log-info "running \"${TESTNAME}\" test suite..."

[ -x "${TESTDIR}"/teardown ] || fail-now "missing required teardown script or it is not executable"
[ -f "${TESTDIR}"/README.md ] || fail-now "missing required README.md file"

# Create a temporary directory to hold the configuration for the test run. On
# darwin, don't use the user temp dir since it is not mountable by default with
# Docker for MacOS (but /tmp is). We need a directory we can mount into the
# running containers for various tests (e.g. to provide webhook configuration
# to the kind node).
RUNDIR=$(_CS_DARWIN_USER_TEMP_DIR='' TMPDIR='' mktemp -d /tmp/spire-integration-XXXXXX)

# The following variables are intended to be usable to step scripts
export ROOTDIR
export REPODIR
export RUNDIR

export SUCCESS=

# Ensure we always clean up after ourselves.
cleanup() {
    # Execute the teardown script and clean up the "run" directory
    log-debug "executing teardown..."

    # shellcheck source=./common
    if ! (source "${COMMON}" && source "${RUNDIR}/teardown"); then
        rm -rf "${RUNDIR}"
        fail-now "\"${TESTNAME}\" failed to tear down."
    fi

    # double check that if docker compose was used that we clean everything up.
    # this helps us to not pollute the local docker state.
    if [ -f "${RUNDIR}/docker-compose.yaml" ]; then
        docker-cleanup
    fi

    rm -rf "${RUNDIR}"
    if [ -n "$SUCCESS" ]; then
        log-success "\"${TESTNAME}\" test suite succeeded."
    else
        fail-now "\"${TESTNAME}\" test suite failed."
    fi
}
trap cleanup EXIT

#################################################
# Prepare the run directory
#################################################

# Prepare common directories used by tests.
# These directories on the host are mapped to paths in containers, possibly
# running with a different user.
mkdir -p -m 777 "${RUNDIR}/conf/agent"
mkdir -p -m 777 "${RUNDIR}/conf/server"

cp -R "${TESTDIR}"/* "${RUNDIR}/"

#################################################
# Execute the test suite
#################################################
run-step() {
    local script="$1"
    if [ ! -x "$script" ]; then
        fail-now "Failing: \"$script\" is not executable"
    fi
    log-debug "executing $(basename "$script")..."

    # Execute the step in a separate bash process that ensures that strict
    # error handling is enabled (e.g. `errexit` and `pipefail`) and sources the
    # common script. A subshell CANNOT be used as an alternative due to the way
    # bash handles `errexit` from subshells (i.e. ignores it).
    bash -s <<STEPSCRIPT
set -e -o pipefail
source "${COMMON}"
source "${script}"
STEPSCRIPT
}

cd "${RUNDIR}" || fail-now "cannot change to run directory"
shopt -s nullglob
steps=( ??-* )
if [ ${#steps[@]} -eq 0 ]; then
    fail-now "test suite has no steps"
fi
for step in "${steps[@]}"; do
    if ! run-step "$step"; then
        fail-now "step $(basename "$step") failed"
    fi
done

export SUCCESS=1
