#!/bin/bash
#
# This script performs a lightweight end-to-end test of the SPIRE server and
# agent using the SQLite database. It creates a registration entry, and uses the SPIRE agent cli tool
# to fetch the minted SVID from the Workload API. This script will exit with
# code 0 if all steps are completed successfully.
#
# If a running docker system is available from the machine this test will also create a new PostgreSQL instance
# as a docker container. This database instance is then used to run the e2e test with PostgreSQL as a datastore.
#
# PLEASE NOTE: This script must be run from the project root, and will remove the
# default datastore file before beginning in order to ensure accurate resutls.
#

set -e


run_e2e_test() {
    rm -f .data/datastore.sqlite3
    CONFIG_LOCATION=$1

    run_test $CONFIG_LOCATION
}

run_docker_test() {
    CONFIG_LOCATION=$1
    DOCKER_COMMAND=$2

    output=$(docker version)
    if [ $? -ne 0 ]; then
        echo "No working docker installation found. Skipping e2e test for configuration file $CONFIG_LOCATION"
        return
    fi

    echo "Starting container $DOCKER_COMMAND"
    CONTAINER_ID=$(docker run $DOCKER_COMMAND)
    sleep 15
    run_test $CONFIG_LOCATION
    docker rm -f $CONTAINER_ID
}

run_test() {
    CONFIG_LOCATION=$1

    ./cmd/spire-server/spire-server run -config $CONFIG_LOCATION &
    SERVER_PID=$!
    sleep 2

    ./cmd/spire-server/spire-server entry create \
    -spiffeID spiffe://example.org/test \
    -parentID spiffe://example.org/agent \
    -selector unix:uid:$(id -u)

    TOKEN=$(./cmd/spire-server/spire-server token generate -spiffeID spiffe://example.org/agent | awk '{print $2}')
    ./cmd/spire-agent/spire-agent run -joinToken $TOKEN &
    AGENT_PID=$!
    sleep 2

    set +e
    RESULT=$(./cmd/spire-agent/spire-agent api fetch x509)
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

    kill $AGENT_PID
    kill $SERVER_PID
    wait

    if [ $CODE -ne "0" ]; then
        exit $CODE
    fi
}

run_e2e_test "conf/server/server.conf"
run_docker_test "test/configs/server/postgres.conf" "-e POSTGRES_PASSWORD=password -p 10864:5432 -d postgres"
run_docker_test "test/configs/server/mysql.conf" "-e MYSQL_PASSWORD=password -e MYSQL_DATABASE=mysql -e MYSQL_USER=mysql -e MYSQL_RANDOM_ROOT_PASSWORD=yes -p 6612:3306 -d mysql:8.0.15"

if [ "$TEST_ALL_DB_VERSIONS" -eq "1" ]; then
    run_docker_test "test/configs/server/mysql.conf" "-e MYSQL_PASSWORD=password -e MYSQL_DATABASE=mysql -e MYSQL_USER=mysql -e MYSQL_RANDOM_ROOT_PASSWORD=yes -p 6612:3306 -d mysql:5.5.62"
    run_docker_test "test/configs/server/mysql.conf" "-e MYSQL_PASSWORD=password -e MYSQL_DATABASE=mysql -e MYSQL_USER=mysql -e MYSQL_RANDOM_ROOT_PASSWORD=yes -p 6612:3306 -d mysql:5.6.43"
    run_docker_test "test/configs/server/mysql.conf" "-e MYSQL_PASSWORD=password -e MYSQL_DATABASE=mysql -e MYSQL_USER=mysql -e MYSQL_RANDOM_ROOT_PASSWORD=yes -p 6612:3306 -d mysql:5.7.25"
fi
