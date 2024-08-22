#!/bin/bash
set -e

SPIFFE_ID="spiffe://example.org/workload"

echo "Checking if entry with SPIFFE ID ${SPIFFE_ID} exists..."
OUTPUT=$(spire-server entry show -spiffeID "${SPIFFE_ID}" 2>&1)

if echo "$OUTPUT" | grep -q "Error"; then
    echo "Error: Entry with SPIFFE ID ${SPIFFE_ID} not found."
    exit 1
else
    echo "Entry with SPIFFE ID ${SPIFFE_ID} exists."
fi

echo "Entry checked successfully."
exit 0