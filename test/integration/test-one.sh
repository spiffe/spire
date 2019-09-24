#!/bin/bash

ROOTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TESTDIR="$(realpath "$1")"
TESTNAME="$(basename "${TESTDIR}")"

SPIRE_SERVER_IMAGE=${SPIRE_SERVER_IMAGE:-spire-server:latest-local}
SPIRE_AGENT_IMAGE=${SPIRE_AGENT_IMAGE:-spire-agent:latest-local}

COMMON="${ROOTDIR}/common"
source "${COMMON}"
if [ -z "${TESTDIR}" ]; then
    log-fail "Missing test directory"
fi

RUNDIR=$(mktemp -d)
SETUP="${TESTDIR}/setup"
TEARDOWN="${TESTDIR}/teardown"

[ -x "${SETUP}" ] || log-fail "Missing teardown script"
[ -x "${TEARDOWN}" ] || log-fail "Missing teardown script"

exec-script() {
    local script="$1"
    if [ ! -x "$script" ]; then
        log-warn "skipping $(basename "$script"); not executable"
        return
    fi
    log-debug "executing $(basename "$script")..."
    (source "${COMMON}" && source "$1")
}

exec-script-opt() {
    if [ -f "$1" ]; then
        exec-script "$1"
    fi
}

replace-image-directives() {
    local dir="$1"
    [ ! -f "${dir}/docker-compose.yml" ] || sed -i.bak "s#SPIRE-SERVER-IMAGE#${SPIRE_SERVER_IMAGE}#g" "${dir}/docker-compose.yml"
    [ ! -f "${dir}/docker-compose.yaml" ] || sed -i.bak "s#SPIRE-SERVER-IMAGE#${SPIRE_SERVER_IMAGE}#g" "${dir}/docker-compose.yaml"
    [ ! -f "${dir}/docker-compose.yml" ] || sed -i.bak "s#SPIRE-AGENT-IMAGE#${SPIRE_AGENT_IMAGE}#g" "${dir}/docker-compose.yml"
    [ ! -f "${dir}/docker-compose.yaml" ] || sed -i.bak "s#SPIRE-AGENT-IMAGE#${SPIRE_AGENT_IMAGE}#g" "${dir}/docker-compose.yaml"
}

cleanup() {
    exec-script "${TEARDOWN}"
    if [ -f "${RUNDIR}/success" ]; then
        log-success "\"${TESTNAME}\" test succeeded."
    else
        log-err "\"${TESTNAME}\" test failed."
    fi
    rm -rf "${RUNDIR}"
}

trap cleanup EXIT

log-info "\"${TESTNAME}\" test starting..."

cd "${RUNDIR}" || fail-now "cannot change to run directory"

exec-script "${SETUP}" && \
    replace-image-directives "${RUNDIR}" && \
    for step in "${TESTDIR}"/??-*; do
        if ! exec-script "$step"; then 
            log-err "step $(basename "$step") failed"
            break
        fi
    done
