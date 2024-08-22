#!/bin/bash
set -e

ENTRIES_FILE="${RUNDIR}/data.json"

# Start the entry creation process in the background
spire-server entry create -data "${ENTRIES_FILE}" &
ENTRY_PID=$!

# Wait for the entry creation process to finish
wait $ENTRY_PID

echo "Entries uploaded successfully."

