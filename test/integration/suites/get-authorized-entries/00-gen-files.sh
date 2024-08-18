#!/bin/bash

# Exit on error
set -e

# Define directories
BASE_DIR="/opt/spire/conf"
SERVER_DIR="${BASE_DIR}/server"
AGENT_DIR="${BASE_DIR}/agent"

# Create necessary directories
mkdir -p "${SERVER_DIR}"
mkdir -p "${AGENT_DIR}"

# Generate Root CA Certificate and Key
echo "Generating Root CA certificate and key..."
openssl genrsa -out root-ca.key 2048
openssl req -new -x509 -key root-ca.key -out root-ca.crt -days 3650 -subj "/CN=SPIRE Root CA"

# Generate Server Certificate and Key
echo "Generating Server certificate and key..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=SPIRE Server"
openssl x509 -req -in server.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out server.crt -days 365

# Generate Agent Certificate and Key
echo "Generating Agent certificate and key..."
openssl genrsa -out agent.key 2048
openssl req -new -key agent.key -out agent.csr -subj "/CN=SPIRE Agent"
openssl x509 -req -in agent.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out agent.crt -days 365

# Create Trust Bundles
echo "Creating trust bundles..."
cat root-ca.crt server.crt > "${SERVER_DIR}/agent-cacert.pem"
cat root-ca.crt agent.crt > "${AGENT_DIR}/bootstrap.crt"

# Combine Certificates and Keys
echo "Creating combined certificate files..."
cat agent.crt agent.key > "${AGENT_DIR}/agent.crt.pem"
cat server.crt server.key > "${SERVER_DIR}/server.crt.pem"

# Create Combined Key and Certificate Files
echo "Creating combined key and certificate files..."
cat agent.key agent.crt > "${AGENT_DIR}/agent.key.pem"
cat server.key server.crt > "${SERVER_DIR}/server.key.pem"

# Clean up intermediate files
echo "Cleaning up..."
rm server.key server.csr server.crt agent.key agent.csr agent.crt

echo "Certificate files generated and placed in ${BASE_DIR}."
