# Agent plugin: WorkloadAttestor "docker"

The `docker` plugin generates selectors based on docker labels for workloads calling the agent.
It does so by retrieving the workload's container ID from its cgroup membership on Unix systems or Job Object names on Windows,
then querying the docker daemon for the container's labels.

| Configuration                  | Description                                                                                    | Default                          |
|--------------------------------|------------------------------------------------------------------------------------------------|----------------------------------|
| docker_socket_path             | The location of the docker daemon socket (Unix)                                                | "unix:///var/run/docker.sock"    |
| docker_version                 | The API version of the docker daemon. If not specified                                         |                                  |
| container_id_cgroup_matchers   | A list of patterns used to discover container IDs from cgroup entries (Unix)                   |                                  |
| docker_host                    | The location of the Docker Engine API endpoint (Windows only)                                  | "npipe:////./pipe/docker_engine" |
| use_new_container_locator      | If true, enables the new container locator algorithm that has support for cgroups v2           | false                            |
| verbose_container_locator_logs | If true, enables verbose logging of mountinfo and cgroup information used to locate containers | false                            |

A sample configuration:

```hcl
    WorkloadAttestor "docker" {
        plugin_data {
        }
    }
```

## Workload Selectors

Since selectors are created dynamically based on the container's docker labels, there isn't a list of known selectors.
Instead, each of the container's labels are used in creating the list of selectors.

| Selector          | Example                                            | Description                                                            |
|-------------------|----------------------------------------------------|------------------------------------------------------------------------|
| `docker:label`    | `docker:label:com.example.name:foo`                | The key:value pair of each of the container's labels.                  |
| `docker:env`      | `docker:env:VAR=val`                               | The raw string value of each of the container's environment variables. |
| `docker:image_id` | `docker:image_id:envoyproxy/envoy:contrib-v1.29.1` | The image name and version of the container.                           |

## Container ID CGroup Matchers

The patterns provided should use the wildcard `*` matching token and `<id>` capture token
to describe how a container id should be extracted from a cgroup entry. The
given patterns MUST NOT be ambiguous and an error will be returned if multiple
patterns can match the same input.

Valid Example:

```hcl
    container_id_cgroup_matchers = [
        "/docker/<id>",
        "/my.slice/*/<id>/*"
    ]
```

Invalid Example:

```hcl
    container_id_cgroup_matchers = [
        "/a/b/<id>",
        "/*/b/<id>"
    ]
```

Note: The pattern provided is *not* a regular expression. It is a simplified matching
language that enforces a forward slash-delimited schema.

## Example

### Image ID

Example of an image_id selector for an Envoy proxy container. First run `docker images` to see the images available:

```shell
$ docker images
REPOSITORY                    TAG               IMAGE ID       CREATED        SIZE
prom/prometheus               latest            1d3b7f56885b   2 weeks ago    262MB
spiffe.io                     latest            02acdde06edc   2 weeks ago    1.17GB
ghcr.io/spiffe/spire-agent    1.9.1             622ce7acc7e8   4 weeks ago    57.9MB
ghcr.io/spiffe/spire-server   1.9.1             e3b24c3cd9e1   4 weeks ago    103MB
envoyproxy/envoy              contrib-v1.29.1   644f45f6626c   7 weeks ago    181MB
```

Then u4se the `REPOSITORY:TAG` as the selector, not the `IMAGE ID` column.

```shell
$ spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/host/foo \
    -selector docker:image_id:envoyproxy/envoy:contrib-v1.29.1
```

### Labels

If a workload container is started with `docker run --label com.example.name=foo [...]`, then workload registration would occur as:

```shell
$ spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/host/foo \
    -selector docker:label:com.example.name:foo
```

You can compose multiple labels as selectors.

```shell
$ spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/host/foo \
    -selector docker:label:com.example.name:foo
    -selector docker:label:com.example.cluster:prod
```

### Environment variables

Example of an environment variable selector for the variable `ENVIRONMENT`
matching a value of `prod`:

```shell
$ spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/host/foo \
    -selector docker:env:ENVIRONMENT=prod
```
