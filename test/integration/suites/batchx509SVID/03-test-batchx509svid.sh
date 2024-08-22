#!/bin/bash
set -e

ENTRIES_FILE="${RUNDIR}/data.json"

# Parse the JSON file and extract SPIFFE IDs
echo "Checking entries from ${ENTRIES_FILE}..."

# Extract SPIFFE IDs using jq
SPIFFE_IDS=$(jq -r '.entries[].spiffe_id' "$ENTRIES_FILE")

# Check each entry's existence
for SPIFFE_ID in $SPIFFE_IDS; do
    echo "Checking if entry with SPIFFE ID ${SPIFFE_ID} exists..."
    OUTPUT=$(spire-server entry show -spiffeID "${SPIFFE_ID}" 2>&1)

    if echo "$OUTPUT" | grep -q "Error"; then
        echo "Error: Entry with SPIFFE ID ${SPIFFE_ID} not found."
        exit 1
    else
        echo "Entry with SPIFFE ID ${SPIFFE_ID} exists."
    fi
done

echo "All entries checked successfully."
exit 0