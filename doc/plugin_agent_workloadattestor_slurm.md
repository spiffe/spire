# Agent plugin: WorkloadAttestor "slurm"

The `slurm` plugin generates selectors for workloads that are part of a
[Slurm](https://slurm.schedmd.com/) job. It inspects the cgroup v2 hierarchy that
`slurmstepd` creates for each job step (under the `slurmstepd.scope`) to determine the
job identifier and the job step of the calling workload.

Because the cgroup hierarchy is created and owned by `slurmstepd` and the kernel — not by
the workload — the job and step derived from it cannot be forged by the workload.

This plugin does not accept any configuration options.

General selectors:

| Selector          | Value                                                                                                        |
|-------------------|--------------------------------------------------------------------------------------------------------------|
| `slurm:job_id`    | The numeric Slurm job id. Emitted when Slurm is configured with `CgroupJobIdPaths=yes` (e.g. `slurm:job_id:3385`). |
| `slurm:sluid`     | The Slurm Lexicographically-sortable Unique ID of the job. Emitted by default (e.g. `slurm:sluid:s5K1KKYAYG5D00`). |
| `slurm:step`      | The job step: a numeric step id or one of `batch`, `extern`, `interactive` (e.g. `slurm:step:0`, `slurm:step:batch`). |

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
