# Agent plugin: WorkloadAttestor "k8s"

The `k8s` plugin generates kubernetes-based selectors for workloads calling the agent.
It does so by retrieving the workload's pod ID from its cgroup membership, then querying
the kubelet for information about the pod.

| Configuration | Description |
| ------------- | ----------- |
| kubelet_read_only_port | The port on which the kubelet has exposed its read-only API. |

| Selector | Value |
| -------- | ----- |
| k8s:ns              | The workload's namespace |
| k8s:sa              | The workload's service account |
| k8s:container-image | The image of the workload's container |
| k8s:container-name  | The name of the workload's container |
| k8s:node-name       | The name of the workload's node |
| k8s:pod-label       | A label given to the the workload's pod |
| k8s:pod-owner       | The name of the workload's pod owner |
| k8s:pod-owner-uid   | The UID of the workload's pod owner |
| k8s:pod-uid         | The UID of the workload's pod |
