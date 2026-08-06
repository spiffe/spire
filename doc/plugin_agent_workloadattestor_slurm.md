# Agent plugin: WorkloadAttestor "slurm"

The `slurm` plugin generates selectors for workloads that are part of a
[Slurm](https://slurm.schedmd.com/) job. It inspects the cgroup v2 hierarchy that
`slurmstepd` creates for each job step (under the `slurmstepd.scope`) to determine the
job identifier and the job step of the calling workload.

Because the cgroup hierarchy is created and owned by `slurmstepd` and the kernel — not by
the workload — the job and step derived from it cannot be forged by the workload. To keep
this guarantee, the plugin only matches the scope at its real location directly under the
root-owned `/system.slice` (i.e. `/system.slice/[<nodename>_]slurmstepd.scope/...`). A
workload with a writable or delegated cgroup subtree (for example a rootless container or a
systemd user session) cannot create cgroups under `/system.slice`, so a look-alike path in
its own subtree is not attested.

This plugin does not accept any configuration options.

General selectors:

| Selector       | Value                                                                                   |
| -------------- | --------------------------------------------------------------------------------------- |
| `slurm:job_id` | Numeric Slurm job id when `CgroupJobIdPaths=yes` is set (e.g. `slurm:job_id:3385`).     |
| `slurm:sluid`  | Slurm SLUID of the job; the default job identifier (e.g. `slurm:sluid:s5K1KKYAYG5D00`). |
| `slurm:step`   | Job step: a number or `batch`/`extern`/`interactive` (e.g. `slurm:step:batch`).         |

Exactly one of `slurm:job_id` or `slurm:sluid` is produced for a given workload, depending
on how Slurm is configured (SLUIDs are the default; numeric job ids require
`CgroupJobIdPaths=yes`). A `slurm:step` selector is always produced alongside it.

A sample configuration:

```hcl
    WorkloadAttestor "slurm" {
    }
```

## Platform support

This plugin is only supported on Unix systems and requires that Slurm is configured to use
the cgroup/v2 plugin (`ProctrackType=proctrack/cgroup` with cgroup v2).
