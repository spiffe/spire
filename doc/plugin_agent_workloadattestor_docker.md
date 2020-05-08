# Agent plugin: WorkloadAttestor "docker"

The `docker` plugin generates selectors based on docker labels for workloads calling the agent.
It does so by retrieving the workload's container ID from its cgroup membership, then querying
the docker daemon for the container's labels.

| Configuration | Description |
| ------------- | ----------- |
| docker_socket_path | The location of the docker daemon socket (default: "unix:///var/run/docker.sock" on unix). |
| docker_version | The API version of the docker daemon. If not specified, the version is negotiated by the client.           |

Since selectors are created dynamically based on the container's docker labels, there isn't a list of known selectors.
Instead, each of the container's labels are used in creating the list of selectors.

| Selector          | Example                             | Description                                           |
| ----------------- | ----------------------------------- | ----------------------------------------------------- |
| `docker:label`    | `docker:label:com.example.name:foo` | The key:value pair of each of the container's labels.                  |
| `docker:env`      | `docker:env:VAR=val`                | The raw string value of each of the container's environment variables. |
| `docker:image_id` | `docker:image_id:77af4d6b9913`      | The image id of the container.                                         |

A sample configuration:

```
    WorkloadAttestor "docker" {
        plugin_data {
        }
    }
```

## Example
### Labels
If a workload container is started with `docker run --label com.example.name=foo [...]`, then workload registration would occur as:
```
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/host/foo \
    -selector docker:label:com.example.name:foo
```

You can compose multiple labels as selectors.
```
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/host/foo \
    -selector docker:label:com.example.name:foo
    -selector docker:label:com.example.cluster:prod
```

### Environment variables

Example of an environment variable selector for the variable `ENVIRONMENT`
matching a value of `prod`:
```
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/host/foo \
    -selector docker:env:ENVIRONMENT=prod
```
