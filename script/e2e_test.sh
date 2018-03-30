#!/bin/bash
#
# This script performs a lightweight end-to-end test of the SPIRE server and
# agent. It creates a registration entry, and uses the SPIRE agent cli tool
# to fetch the minted SVID from the Workload API. This script will exit with
# code 0 if all steps are completed successfully.
#
# PLEASE NOTE: This script must be run from the project root, and will remove the
# default datastore file before beginning in order to ensure accurate resutls.
#

if [[ $(uname -s) == "Darwin" ]]; then
	echo "This test is not Darwin compatible, exiting"
	exit 0
fi

set -e

rm -f .data/datastore.sqlite3
./cmd/spire-server/spire-server run &
sleep 2

./cmd/spire-server/spire-server entry create \
-spiffeID spiffe://example.org/test \
-parentID spiffe://example.org/agent \
-selector unix:uid:$(id -u)

TOKEN=$(./cmd/spire-server/spire-server token generate -spiffeID spiffe://example.org/agent | awk '{print $2}')
./cmd/spire-agent/spire-agent run -joinToken $TOKEN &
sleep 2

set +e
RESULT=$(./cmd/spire-agent/spire-agent api fetch)
echo $RESULT | grep "Received 1 bundle"
if [ $? != 0 ]; then
    CODE=1
    echo
    echo
    echo $RESULT
    echo
    echo "Test failed."
    echo
else
    CODE=0
    echo
    echo
    echo "Test passed."
    echo
fi

kill %2
kill %1
wait

exit $CODE
