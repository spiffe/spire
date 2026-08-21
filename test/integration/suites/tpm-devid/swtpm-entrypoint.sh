#!/bin/sh
# Runs a software TPM and exposes it as a unix socket for the agent to attest
# against. go-tpm dials the socket and speaks the emulator protocol, so no TPM
# kernel device or extra container privileges are needed.
set -e

STATE_DIR=/tpmstate
SOCKET_DIR=/tpm

mkdir -p "${STATE_DIR}" "${SOCKET_DIR}"

# The agent runs as a different user than this container's root, so the socket
# has to be group/world accessible once swtpm has created it. Wait for it in the
# background, because swtpm is exec'd below and replaces this shell.
(
    i=0
    while [ ! -S "${SOCKET_DIR}/swtpm.sock" ]; do
        i=$((i + 1))
        if [ "${i}" -gt 100 ]; then
            echo "swtpm did not create ${SOCKET_DIR}/swtpm.sock" >&2
            exit 1
        fi
        sleep 0.1
    done
    chmod 0666 "${SOCKET_DIR}/swtpm.sock"
) &

# exec so swtpm becomes PID 1 and receives SIGTERM from docker directly. Left as
# a child of the shell it would never see the signal, because the kernel does not
# apply default signal actions to PID 1, and teardown would wait out the kill
# timeout on every run.
exec swtpm socket \
    --tpm2 \
    --tpmstate dir="${STATE_DIR}" \
    --ctrl type=unixio,path="${SOCKET_DIR}/swtpm.ctrl" \
    --server type=unixio,path="${SOCKET_DIR}/swtpm.sock" \
    --flags startup-clear
