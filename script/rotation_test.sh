#!/bin/bash
#
# This script implements a simple rotation test. It takes exactly one argument, the number of
# seconds to run. The default is 600.
#
# It works by registering a short-lived entry (60s), and repeatedly hitting the workload API.
# The retrieved SVID is then tested for validity against the received bundle. The test will
# end early if an invalid SVID or bundle is encountered.
#
# It may be desirable to run this test with a low UpstreamCA TTL setting.
#

TIMEOUT=${1:-600}

START=`date +%s`
END=$(($START + $TIMEOUT))

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
-selector unix:uid:$(id -u) \
-ttl 60

TOKEN=$(./cmd/spire-server/spire-server token generate -spiffeID spiffe://example.org/agent | awk '{print $2}')
./cmd/spire-agent/spire-agent run -joinToken $TOKEN &

set +e

function finish ()
{
    kill %2
    kill %1
    wait
    rm bundle.0.pem
    rm svid.0.pem
    rm svid.0.key
}

while [ $? == 0 ]; do
    if [ $END -lt $(date +%s) ]; then
        finish
        echo
        echo
        echo "Test done."
        exit 0
    fi

    sleep 5
    ./cmd/spire-agent/spire-agent api fetch -write .
    RESULT=$(openssl verify -partial_chain -CAfile bundle.0.pem svid.0.pem)
done

finish
echo
echo
echo $RESULT
echo
echo "Test failed."

