#!/bin/bash

setup-tests() {
    # Bring up servers
    docker-up upstream-spire-server
    docker-up downstream-federated-spire-server

    # Bootstrap agents
    log-debug "bootstrapping downstream federated agent..."
    docker compose exec -T downstream-federated-spire-server \
        /opt/spire/bin/spire-server bundle show > conf/downstream-federated/agent/bootstrap.crt
    
    log-debug "bootstrapping upstream agent..."
    docker compose exec -T upstream-spire-server \
        /opt/spire/bin/spire-server bundle show > conf/upstream/agent/bootstrap.crt

    docker compose exec -T upstream-spire-server \
        /opt/spire/bin/spire-server bundle show > conf/downstream/agent/bootstrap.crt
    
    log-debug "creating federation relationship from downstream federated to upstream server and set bundle in same command..."
    docker compose exec -T downstream-federated-spire-server \
        /opt/spire/bin/spire-server bundle show -format spiffe > conf/upstream/server/federated-domain.test.bundle

    # On macOS, there can be a delay propagating the file on the bind mount to the other container
    sleep 1

    docker compose exec -T upstream-spire-server \
        /opt/spire/bin/spire-server federation create \
        -bundleEndpointProfile "https_spiffe" \
        -bundleEndpointURL "https://downstream-federated-spire-server:8443" \
        -endpointSpiffeID "spiffe://federated-domain.test/spire/server" \
        -trustDomain "federated-domain.test" \
        -trustDomainBundleFormat "spiffe" \
        -trustDomainBundlePath "/opt/spire/conf/server/federated-domain.test.bundle"
    
    log-debug "bootstrapping bundle from upstream to downstream federated server..."
    docker compose exec -T upstream-spire-server \
        /opt/spire/bin/spire-server bundle show -format spiffe > conf/downstream-federated/server/domain.test.bundle

    # On macOS, there can be a delay propagating the file on the bind mount to the other container
    sleep 1

    docker compose exec -T downstream-federated-spire-server \
        /opt/spire/bin/spire-server bundle set -format spiffe -id spiffe://domain.test -path /opt/spire/conf/server/domain.test.bundle

    log-debug "creating federation relationship from upstream to downstream federated server..."
    docker compose exec -T downstream-federated-spire-server \
        /opt/spire/bin/spire-server federation create \
        -bundleEndpointProfile "https_spiffe" \
        -bundleEndpointURL "https://upstream-spire-server" \
        -endpointSpiffeID "spiffe://domain.test/spire/server" \
        -trustDomain "spiffe://domain.test"

    # Register workloads
    log-debug "creating registration entry for downstream federated proxy..."
    docker compose exec -T downstream-federated-spire-server \
        /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://federated-domain.test/spire/agent/x509pop/$(fingerprint conf/downstream-federated/agent/agent.crt.pem)" \
        -spiffeID "spiffe://federated-domain.test/downstream-proxy" \
        -selector "unix:uid:0" \
        -federatesWith "spiffe://domain.test" \
        -ttl 0
    
    log-debug "creating registration entry for upstream proxy..."
    docker compose exec -T upstream-spire-server \
        /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://domain.test/spire/agent/x509pop/$(fingerprint conf/upstream/agent/agent.crt.pem)" \
        -spiffeID "spiffe://domain.test/upstream-proxy" \
        -selector "unix:uid:0" \
        -federatesWith "spiffe://federated-domain.test" \
        -ttl 0

    log-debug "creating registration entry for downstream proxy..."
    docker compose exec -T upstream-spire-server \
        /opt/spire/bin/spire-server entry create \
        -parentID "spiffe://domain.test/spire/agent/x509pop/$(fingerprint conf/downstream/agent/agent.crt.pem)" \
        -spiffeID "spiffe://domain.test/downstream-proxy" \
        -selector "unix:uid:0" \
        -ttl 0
}

test-envoy() {
    mTLSSocat=$1
    tlsSocat=$2
    
    local max_checks_per_port=15
    local check_interval=1
	
    # Remove howdy, it i necessary for VERIFY to get again messages
    docker compose exec -T upstream-socat rm -f /tmp/howdy
    
    log-debug "Checking mTLS: ${mTLSSocat}"
    TRY() { docker compose exec -T ${mTLSSocat} /bin/sh -c 'echo HELLO_MTLS | socat -u STDIN TCP:localhost:8001'; }
    VERIFY() { docker compose exec -T upstream-socat cat /tmp/howdy | grep -q HELLO_MTLS; }
    
    local mtls_federated_ok=
    for ((i=1;i<=max_checks_per_port;i++)); do
        log-debug "Checking MTLS proxy ($i of $max_checks_per_port max)..."
        if TRY && VERIFY ; then
            mtls_federated_ok=1
            log-info "MTLS proxy OK"
            break
        fi
        sleep "${check_interval}"
    done
    
    log-debug "Checking TLS: ${tlsSocat}"
    TRY() { docker compose exec -T ${tlsSocat} /bin/sh -c 'echo HELLO_TLS | socat -u STDIN TCP:localhost:8002'; }
    VERIFY() { docker compose exec -T upstream-socat cat /tmp/howdy | grep -q HELLO_TLS; }
    
    tls_federated_ok=
    for ((i=1;i<=max_checks_per_port;i++)); do
        log-debug "Checking TLS proxy ($i of $max_checks_per_port max)..."
        if TRY && VERIFY ; then
            tls_federated_ok=1
            log-info "TLS proxy OK"
            break
        fi
        sleep "${check_interval}"
    done
    
    if [ -z "${mtls_federated_ok}" ]; then
        fail-now "MTLS Proxying failed"
    fi
    
    if [ -z "${tls_federated_ok}" ]; then
        fail-now "TLS Proxying failed"
    fi
}

"${ROOTDIR}/setup/x509pop/setup.sh" conf/downstream-federated/server conf/downstream-federated/agent
"${ROOTDIR}/setup/x509pop/setup.sh" conf/upstream/server conf/upstream/agent conf/downstream/agent

# Test at most the last five minor releases.
MAX_ENVOY_RELEASES_TO_TEST=5

# Don't test earlier than v1.13, when was the first release to include the v3
# API.
EARLIEST_ENVOY_RELEASE_TO_TEST=v1.18

envoy-releases

log-info "Releases to test: ${ENVOY_RELEASES_TO_TEST[@]}"

# Do some preliminary setup
setup-tests

# Execute the tests for each release under test. The spire-server should remain
# up across these tests to minimize teardown/setup costs that are tangential
# to the support (since we're only testing the SDS integration).
for release in "${ENVOY_RELEASES_TO_TEST[@]}"; do
    log-info "Building Envoy ${release}..."
    build-mashup-image "${release}"

    log-info "Testing Envoy ${release}..."

    docker-up

    test-envoy "downstream-socat-mtls" "downstream-socat-tls"
    test-envoy "downstream-federated-socat-mtls" "downstream-federated-socat-tls"

    # stop and clear everything but the server container
    docker compose stop \
        upstream-proxy \
        downstream-proxy \
        downstream-federated-proxy \
        upstream-socat \
        downstream-socat-mtls \
        downstream-socat-tls \
        downstream-federated-socat-mtls \
        downstream-federated-socat-tls

    docker compose rm -f
done
