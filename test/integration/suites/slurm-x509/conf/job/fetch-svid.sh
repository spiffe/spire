#!/bin/bash
#SBATCH --job-name=spire-fetch
#SBATCH --output=/tmp/slurm-spire-jobs/slurm-%j.out
#SBATCH --error=/tmp/slurm-spire-jobs/slurm-%j.out
#SBATCH --time=00:05:00

# Batch job payload: block retrying `spire-agent api fetch x509` until the
# matching registration entry has been created and synced to the agent, then
# write the SVID and a SUCCESS marker. Runs as a host process inside the Slurm
# job's cgroup (.../slurmstepd.scope/job_<id>/step_batch/...).

set -u

SOCK="/tmp/slurm-spire-sockets/workload_api.sock"
BIN="/usr/local/bin/spire-agent"
WORKDIR="/tmp/slurm-spire-jobs/${SLURM_JOB_ID}"
MARKER="${WORKDIR}/SUCCESS"

mkdir -p "${WORKDIR}"

echo "job ${SLURM_JOB_ID}: cgroup =================================="
cat /proc/self/cgroup
echo "==========================================================="

DEADLINE=$(( $(date +%s) + 120 ))
attempt=0
while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
    attempt=$((attempt + 1))
    echo "job ${SLURM_JOB_ID}: fetch attempt ${attempt}..."
    if OUT=$("${BIN}" api fetch x509 -socketPath "${SOCK}" -write "${WORKDIR}" 2>&1); then
        if [ -f "${WORKDIR}/svid.0.pem" ]; then
            echo "${OUT}" | grep -m1 "SPIFFE ID" | sed 's/.*SPIFFE ID:[[:space:]]*/SPIFFE_ID=/' | tee "${MARKER}"
            echo "FETCH_SUCCESS job=${SLURM_JOB_ID}" | tee -a "${MARKER}"
            echo "${OUT}"
            exit 0
        fi
    fi
    echo "job ${SLURM_JOB_ID}: not issued yet: ${OUT}"
    sleep 3
done

echo "FETCH_TIMEOUT job=${SLURM_JOB_ID}"
exit 1
