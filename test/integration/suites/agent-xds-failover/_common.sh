# Helpers shared by the JWT-fetch steps. This file does not match the ??-*
# step glob, so the harness does not execute it as a step; steps source it
# explicitly.

# unique-audience prints a JWT audience that is essentially never reused, which
# forces a JWT-SVID cache miss so the fetch results in a live NewJWTSVID RPC to
# whichever server the xDS load balancer currently points at.
unique-audience() {
    echo "aud-$(date +%s%N)-${RANDOM}"
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

# extract-jwt prints the first JWT (header.payload.signature) found in stdin, or
# nothing if there is none. It always succeeds so that "no token" does not trip
# the steps' errexit/pipefail.
extract-jwt() {
    grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -n1 || true
}

# fetch-jwt-kid <audience> fetches a JWT-SVID for uid 1001 and prints the "kid"
# from the JWT header. The kid identifies the signing key, which is unique per
# server, so it tells us which server issued the token. It retries to absorb the
# brief window while the xDS priority policy fails over between servers, and
# fails the step if no token is obtained.
fetch-jwt-kid() {
    local aud="$1"
    local out token kid
    for ((i=1;i<=30;i++)); do
        out=$(docker compose exec -u 1001 -T spire-agent \
            /opt/spire/bin/spire-agent api fetch jwt -audience "${aud}" \
            -socketPath /opt/spire/sockets/workload_api.sock 2>/dev/null || true)
        token=$(echo "${out}" | extract-jwt)
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

# expect-jwt-fetch-fails <audience> asserts that a bounded series of fetch
# attempts never yields a token (used when no server is available).
expect-jwt-fetch-fails() {
    local aud="$1" out token
    for ((i=1;i<=10;i++)); do
        out=$(docker compose exec -u 1001 -T spire-agent \
            /opt/spire/bin/spire-agent api fetch jwt -audience "${aud}" \
            -socketPath /opt/spire/sockets/workload_api.sock 2>/dev/null || true)
        token=$(echo "${out}" | extract-jwt)
        if [ -n "${token}" ]; then
            fail-now "expected JWT fetch to fail with no servers available, but got a token"
        fi
        sleep 1
    done
}
