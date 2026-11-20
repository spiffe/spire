# Running SPIRE with gVisor

[gVisor](https://gvisor.dev) (runsc) is a user-space sandbox runtime for
containers. This guide covers the two configuration steps needed for SPIRE
workload attestation to work correctly in gVisor pods on Kubernetes.

## Prerequisites

- gVisor installed and configured as a Kubernetes RuntimeClass
- SPIRE Agent deployed as a DaemonSet with the k8s workload attestor enabled

## Enable host UDS access

By default gVisor does not allow workloads to connect to host Unix domain
sockets. Set `host-uds = "open"` in the runsc configuration so workloads can
reach the SPIRE agent socket:

```toml
# /etc/runsc/config.toml  (or equivalent containerd/CRI-O shim config)
host-uds = "open"
```

Alternatively, when the containerd shim is configured to forward `dev.gvisor.*`
annotations (see [gVisor containerd quick start](https://gvisor.dev/docs/user_guide/quick_start/kubernetes/)),
you can set this per-pod:

```yaml
metadata:
  annotations:
    dev.gvisor.flag.host-uds: open
```

`host-uds` is on gVisor's annotation allowlist and does not require
`--allow-flag-override`. See the [gVisor networking docs](https://gvisor.dev/docs/user_guide/networking/)
for details on per-sandbox annotation overrides.

## Configure the agent

With `host-uds = "open"`, the gVisor gofer process proxies workload connections
to the agent socket using its elevated capabilities. This causes the connecting
credentials seen by the agent to differ from the gofer's host identity. Enable
the capability-based bypass so the agent accepts these connections:

```hcl
agent {
    # ...
    allow_uid_mismatch = true
}
```

A mismatch is accepted only when the connecting process holds the appropriate
Linux capabilities. Connections that cannot be explained this way are still
rejected.

## Container identity

Because gofer processes run in the sandbox (pause) cgroup rather than their
individual container cgroups, the k8s workload attestor cannot resolve a
container ID. Container-level selectors (`container-name`, `container-image`)
are therefore not produced for gVisor pods.

Use `disable_container_selectors = true` in the k8s workload attestor plugin to
fall back to pod-level selectors:

```hcl
WorkloadAttestor "k8s" {
    plugin_data {
        disable_container_selectors = true
    }
}
```
