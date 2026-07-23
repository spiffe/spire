# slurm-x509 suite

## Description

This suite validates the agent `slurm` WorkloadAttestor end to end against a real
single-node Slurm cluster.

Slurm's cgroup/v2 support (the `slurmstepd.scope/<job>/step_<x>/...` hierarchy the attestor
matches) requires Slurm >= 22.05 with a host systemd + dbus + cgroup v2. To get that reliably,
this suite runs **Slurm 23.11 directly on the host** (the integration job runs on
`ubuntu-24.04`), while SPIRE runs in containers as in the other suites.

Topology:

- `slurmctld` + `slurmd` + `munged` run on the host (native systemd/cgroup v2).
- `spire-server` runs in a container.
- `spire-agent` runs in a container that shares the host PID and cgroup namespaces
  (`pid: host`, `cgroup: host`). This lets the containerized agent attest a host Slurm job:
  `SO_PEERCRED` returns the job's real host PID, and `/proc/<pid>/cgroup` shows the full
  `slurmstepd.scope/...` path. The workload API socket is bind-mounted to a host directory so
  the host job can connect to it.

The test submits a batch job that blocks retrying `spire-agent api fetch x509` until an SVID is
issued. Meanwhile the test reads the job id from `squeue`, creates a registration entry with
`slurm:job_id:<jobid>` + `slurm:step:batch` selectors, and then verifies the job fetched its
SVID.
