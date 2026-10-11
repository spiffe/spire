# Helpers shared by the JWT-fetch steps. This file does not match the ??-*
# step glob, so the harness does not execute it as a step; steps source it
# explicitly.

# unique-audience prints a JWT audience that is essentially never reused, which
# forces a JWT-SVID cache miss so the fetch results in a live NewJWTSVID RPC to
# whichever server the xDS load balancer currently points at.
unique-audience() {
    echo "aud-$(date +%s%N)-${RANDOM}"
}

# server-jwt-kid <service> prints the server's active JWT signing kid.
server-jwt-kid() {
    docker compose exec -T "$1" /opt/spire/bin/spire-server \
        localauthority jwt show -output json | jq -r .active.authority_id
}

# decode-base64url decodes a base64url-encoded string (as used in JWT segments).
decode-base64url() {
    local d="${1//-/+}"
    d="${d//_//}"
    case $(( ${#d} % 4 )) in
        2) d="${d}==";;
        3) d="${d}=";;
    esac
    echo "${d}" | base64 -d 2>/dev/null || true
}

# fetch-jwt-kid <audience> fetches a JWT-SVID for uid 1001 and prints the "kid"
# from the JWT header. The kid identifies the signing key, which is unique per
# server, so it tells us which server issued the token. It retries to absorb the
# brief window while the xDS priority policy fails over between servers, and
# fails the step if no token is obtained.
fetch-jwt-kid() {
    local aud="$1"
    local token kid
    for ((i=1;i<=30;i++)); do
        token=$(docker compose exec -u 1001 -T spire-agent \
            /opt/spire/bin/spire-agent api fetch jwt -audience "${aud}" -output json \
            -socketPath /opt/spire/sockets/workload_api.sock 2>/dev/null \
            | jq -r '.[0].svids[0].svid // empty' 2>/dev/null || true)
        if [ -n "${token}" ]; then
            kid=$(decode-base64url "$(echo "${token}" | cut -d. -f1)" | jq -r '.kid' 2>/dev/null || true)
            if [ -n "${kid}" ] && [ "${kid}" != "null" ]; then
                echo "${kid}"
                return 0
            fi
        fi
        sleep 1
    done
    fail-now "failed to fetch a JWT-SVID for audience ${aud}"
}

# expect-jwt-fetch-fails <audience> asserts that the agent itself rejects the
# fetch because no server is reachable, and that the agent is still running.
# The CLI timeout exceeds the agent's 30s NewJWTSVID retry window so the error
# comes from the agent, not from the CLI deadline.
expect-jwt-fetch-fails() {
    local aud="$1" out
    if out=$(docker compose exec -u 1001 -T spire-agent \
        /opt/spire/bin/spire-agent api fetch jwt -audience "${aud}" -timeout 45s \
        -socketPath /opt/spire/sockets/workload_api.sock 2>&1); then
        fail-now "expected JWT fetch to fail with no servers available, but it succeeded: ${out}"
    fi
    if ! echo "${out}" | grep -q "code = Unavailable desc = could not fetch JWT-SVID"; then
        fail-now "JWT fetch failed for an unexpected reason: ${out}"
    fi
    if [ -z "$(docker compose ps -q --status running spire-agent)" ]; then
        fail-now "spire-agent is not running"
    fi
}
