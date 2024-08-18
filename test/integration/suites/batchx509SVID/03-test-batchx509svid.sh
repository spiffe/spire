#!/bin/bash

# Define the SPIRE server address
SPIRE_SERVER_ADDRESS="localhost:8081"

# Define the correct API endpoint for Batchx509SVID
API_ENDPOINT="${SPIRE_SERVER_ADDRESS}/v1/batchx509svid"

# Wait for SPIRE server to be ready
echo "Waiting for SPIRE server to be ready..."
for i in {1..10}; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "${SPIRE_SERVER_ADDRESS}")
    if [ "$response" -eq 200 ]; then
        echo "SPIRE server is ready."
        break
    fi
    sleep 2
done

# Make a request to the Batchx509SVID endpoint
echo "Testing Batchx509SVID RPC..."
response=$(curl -s -o /dev/null -w "%{http_code}" "${API_ENDPOINT}")

# Check if the response code is 200 (OK)
if [ "$response" -ne 200 ]; then
    echo "Error: Expected HTTP 200 OK but received HTTP $response"
    exit 1
else
    echo "Batchx509SVID RPC is working as expected."
fi
