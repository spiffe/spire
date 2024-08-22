#!/bin/bash

set -e

"${ROOTDIR}/setup/x509pop/setup.sh" conf/server conf/agent

"${ROOTDIR}/setup/debugserver/build.sh" "${RUNDIR}/conf/server/debugclient"
"${ROOTDIR}/setup/debugagent/build.sh" "${RUNDIR}/conf/agent/debugclient"


echo "Starting SPIRE server..."
spire-server run -config conf/server/server.conf > ${RUNDIR}/spire-server.log 2>&1 &
SERVER_PID=$!
sleep 5

echo "Starting SPIRE agent..."
spire-agent run -config conf/agent/agent.conf &
AGENT_PID=$!
sleep 5