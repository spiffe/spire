#!/bin/bash

set -eo pipefail

log-debug "verifying token renewal..."

timeout=$(gdate -ud "1 minute 30 second" +%s)
count=0

while [ $(gdate -u +%s) -lt $timeout ]; do
  count=`./bin/kubectl logs -n spire $(./bin/kubectl get pod -n spire -o name) | echo "$(grep "Successfully renew auth token" || [[ $? == 1 ]])" | wc -l`
  if [ $count -ge 2 ]; then
    log-info "token renewal is verified"
    exit 0
  fi
  sleep 10
done

fail-now "expected number of token renewal log not found"
