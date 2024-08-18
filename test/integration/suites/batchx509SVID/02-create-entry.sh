#!/bin/bash
set -e

# Function to check if the entry exists
check_entry_exists() {
    local entry_id=$1
    local retries=10
    local delay=5

    for ((i=1; i<=retries; i++)); do
        echo "Checking if entry with SPIFFE ID $entry_id exists (attempt $i)..."

        # Check if the entry exists using `spire-server entry show`
        response=$(spire-server entry show -spiffeID "$entry_id" 2>&1)

        # Check if the response contains the expected entry
        if echo "$response" | grep -q "SPIFFE ID"; then
            echo "Entry with SPIFFE ID $entry_id found."
            return 0
        fi

        echo "Entry with SPIFFE ID $entry_id not found yet. Retrying in $delay seconds..."
        sleep "$delay"
    done

    echo "Failed to create entry within the timeout period."
    return 1
}

# Create the registration entry
echo "Creating registration entry..."
spire-server entry create -parentID spiffe://example.org/spire/agent/x509pop/agent1 \
                         -spiffeID spiffe://example.org/workload \
                         -selector unix:uid:1000 \
                         -x509SVIDTTL 3600 \
                         -jwtSVIDTTL 3600 \
                         -downstream

# Check if the entry exists
check_entry_exists "spiffe://example.org/workload"
