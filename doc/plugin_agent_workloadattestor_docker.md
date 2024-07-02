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

## Sigstore experimental feature

This feature extends the `docker` workload attestor with the ability to validate container image signatures and attestations using the [Sigstore](https://www.sigstore.dev/) ecosystem.

### Experimental options

| Option     | Description                                                                             |
|------------|-----------------------------------------------------------------------------------------|
| `sigstore` | Sigstore options. Options described below. See [Sigstore options](#sigstore-options)    |

### Sigstore options

| Option                 | Description                                                                                                                                                                                                                                                       |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `allowed_identities`   | Maps OIDC Provider URIs to lists of allowed subjects. Supports regular expressions patterbs. Defaults to empty. If unspecified, signatures from any issuer are accepted. (eg. `"https://accounts.google.com" = ["subject1@example.com","subject2@example.com"]`). |
| `skipped_images`       | Lists image IDs to exclude from Sigstore signature verification. For these images, no Sigstore selectors will be generated. Defaults to an empty list.                                                                                                            |
| `rekor_url`            | Specifies the Rekor URL for transparency log verification. Default is the public Rekor instance [https://rekor.sigstore.dev](https://rekor.sigstore.dev).                                                                                                         |
| `ignore_tlog`          | If set to true, bypasses the transparency log verification and the selectors based on the Rekor bundle are not generated.                                                                                                                                         |
| `ignore_attestations`  | If set to true, bypasses the image attestations verification and the selector `image-attestations:verified` is not generated.                                                                                                                                     |
| `ignore_sct`           | If set to true, bypasses the Signed Certificate Timestamp (SCT) verification.                                                                                                                                                                                     |
| `registry_credentials` | Maps each registry URL to its corresponding authentication credentials. Example: `{"docker.io": {"username": "user", "password": "pass"}}`.                                                                                                                       |

#### Custom CA Roots

Custom CA roots signed through TUF can be provided using the `cosign initialize` command. This method securely pins the
CA roots, ensuring that only trusted certificates are used during validation. Additionally, trusted roots for
certificate validation can be specified via the `SIGSTORE_ROOT_FILE` environment variable. For more details on Cosign
configurations, refer to the [documentation](https://github.com/sigstore/cosign/blob/main/README.md).

## Workload Selectors

Since selectors are created dynamically based on the container's docker labels, there isn't a list of known selectors.
Instead, each of the container's labels are used in creating the list of selectors.

| Selector          | Example                                            | Description                                                            |
|-------------------|----------------------------------------------------|------------------------------------------------------------------------|
| `docker:label`    | `docker:label:com.example.name:foo`                | The key:value pair of each of the container's labels.                  |
| `docker:env`      | `docker:env:VAR=val`                               | The raw string value of each of the container's environment variables. |
| `docker:image_id` | `docker:image_id:envoyproxy/envoy:contrib-v1.29.1` | The image name and version of the container.                           |

Sigstore enabled selectors (available when configured to use `sigstore`)

| Selector                                      | Value                                                                                                                                                                                                                                     |
|-----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| docker:image-signature:verified               | When the image signature was verified and is valid.                                                                                                                                                                                       |
| docker:image-attestations:verified            | When the image attestations were verified and are valid.                                                                                                                                                                                  |
| docker:image-signature-value                  | The base64 encoded value of the signature (eg. `k8s:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=`)                                                            |
| docker:image-signature-subject                | The OIDC principal that signed the image (e.g., `k8s:image-signature-subject:spirex@example.com`)                                                                                                                                         |
| docker:image-signature-issuer                 | The OIDC issuer of the signature (e.g., `k8s:image-signature-issuer:https://accounts.google.com`)                                                                                                                                         |
| docker:image-signature-log-id                 | A unique LogID for the Rekor transparency log entry (eg. `k8s:image-signature-log-id:c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b95918123`)                                                                                   |
| docker:image-signature-log-index              | The log index for the Rekor transparency log entry (eg. `k8s:image-signature-log-index:105695637`)                                                                                                                                        |
| docker:image-signature-integrated-time        | The time (in Unix timestamp format) when the image signature was integrated into the signature transparency log (eg. `k8s:image-signature-integrated-time:1719237832`)                                                                    |
| docker:image-signature-signed-entry-timestamp | The base64 encoded signed entry (signature over the logID, logIndex, body and integratedTime) (eg. `k8s:image-signature-integrated-time:MEQCIDP77vB0/MEbR1QKZ7Ol8PgFwGEEvnQJiv5cO7ATDYRwAiB9eBLYZjclxRNaaNJVBdQfP9Y8vGVJjwdbisme2cKabc`)  |

If `ignore_tlog` is set to `true`, the selectors based on the Rekor bundle (`-log-id`, `-log-index`, `-integrated-time`, and `-signed-entry-timestamp`) are not generated.

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
