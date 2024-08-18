#!/bin/bash
set -e

echo "Creating Node-Alias registration entry..."
spire-server entry create -spiffeID spiffe://example.org/workload -parentID spiffe://example.org/spire/agent/x509pop/agent1 -selector "node-alias:node-alias-value"
