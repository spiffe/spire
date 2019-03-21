# Helper functions for exercising e2e tests.

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


