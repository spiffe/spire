#!/bin/sh

set -e -o pipefail

# Configure Root CA
vault secrets enable transit
vault secrets tune -max-lease-ttl=8760h transit
