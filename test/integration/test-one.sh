#!/bin/bash

ROOTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TESTDIR="$(realpath "$1")"
TESTNAME="$(basename "${TESTDIR}")"

SPIRE_SERVER_IMAGE=${SPIRE_SERVER_IMAGE:-spire-server:latest-local}
SPIRE_AGENT_IMAGE=${SPIRE_AGENT_IMAGE:-spire-agent:latest-local}
K8S_WORKLOAD_REGISTRAR_IMAGE=${K8S_WORKLOAD_REGISTRAR_IMAGE:-k8s-workload-registrar:latest-local}

COMMON="${ROOTDIR}/common"
source "${COMMON}"
if [ -z "${TESTDIR}" ]; then
    log-fail "missing test directory"
fi

# Create a temporary directory to hold the configuration for the test run. On
# darwin, don't use the user temp dir since it is not mountable by default with
# Docker for MacOS (but /tmp is). We need a directory we can mount into the
# running containers for various tests (e.g. to provide webhook configuration
# to the kind node).
RUNDIR=$(_CS_DARWIN_USER_TEMP_DIR= TMPDIR= mktemp -d /tmp/spire-integration-XXXXXX)

exec-script() {
    local script="$1"
    if [ ! -x "$script" ]; then
        log-warn "skipping \"$script\"; not executable"
        return
    fi
    log-debug "executing $(basename "$script")..."
    (source "${COMMON}" && source "$script")
}

exec-script-opt() {
    if [ -f "$1" ]; then
        exec-script "$1"
    fi
}

cleanup() {
    exec-script-opt "${RUNDIR}/99-teardown"
    if [ -f "${RUNDIR}/success" ]; then
        log-success "\"${TESTNAME}\" test succeeded."
    else
        log-err "\"${TESTNAME}\" test failed."
    fi
    rm -rf "${RUNDIR}"
}

trap cleanup EXIT

#################################################
# Prepare the run directory
#################################################
log-info "preparing \"${TESTNAME}\"..."
cp -R "${TESTDIR}"/* "${RUNDIR}/"
find "${RUNDIR}" -type f | xargs -n1 sed -i.bak "s#SPIRE-SERVER-IMAGE#${SPIRE_SERVER_IMAGE}#g"
find "${RUNDIR}" -type f | xargs -n1 sed -i.bak "s#SPIRE-AGENT-IMAGE#${SPIRE_AGENT_IMAGE}#g"
find "${RUNDIR}" -type f | xargs -n1 sed -i.bak "s#K8S-WORKLOAD-REGISTRAR-IMAGE#${K8S_WORKLOAD_REGISTRAR_IMAGE}#g"
find "${RUNDIR}" -type f -name "*.bak" | xargs rm

SETUP="${RUNDIR}/00-setup"
TEARDOWN="${RUNDIR}/99-teardown"
[ -x "${SETUP}" ] || log-fail "missing required 00-setup script"
[ -x "${TEARDOWN}" ] || log-fail "missing required 99-teardown script"

#################################################
# Execute the test
#################################################
log-info "running \"${TESTNAME}\"..."

cd "${RUNDIR}" || fail-now "cannot change to run directory"
for step in "${RUNDIR}"/??-*; do
    # The teardown script is invoked explicitly during cleanup
    [ "${step}" != "${TEARDOWN}" ] || continue

    if ! exec-script "$step"; then 
        log-err "step $(basename "$step") failed"
        break
    fi
done
