# Running Docker images as a non-root user

## Background

The SPIRE release images are built from scratch and are designed to contain only the software necessary to run the SPIRE binary.
A consequence of using stripped-down images from scratch is that they do not contain a shell or a full [Linux filesystem](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html).

A general security best practice is to run containers as a designated non-root user to avoid giving unnecessary privileges to the container.
By default, Docker launches containers as the root user.
The scratch base image only provides permission to the root user to create directories at the root of the filesystem.

SPIRE Server and Agent both manage a data directory on disk.
They will attempt to create this data directory on startup if it doesn't already exist.
This operation may fail when using the release images if the container is running as a non-root user and the top-level component of the configured data directory does not exist.
For example, if the data directory is under a top-level path `/myspire` that doesn't exist in the published release images and is not provided from any volume mount, SPIRE will try to create this directory and fail because only root has permission to create files and directories at `/`.
This error will cause the SPIRE container to fail to start up.

## Recommended ways to run SPIRE images as non-root user

### (Simple) Option 1) Use default paths provided in example configuration file

[conf/server/server_container.conf](../conf/server/server_container.conf) and [conf/agent/agent_container.conf](../conf/agent/agent_container.conf) reference the default paths for each common directory that SPIRE Server and Agent read from, write to, and create at runtime, respectively.
All of these directories referenced in those configuration files are provided in the release images with correct permissions for a user with uid `1000` and gid `1000`.
To run the SPIRE containers based off these configuration files, run the container as uid `1000` and gid `1000`.
Note that you will also need to ensure the SPIRE Server configuration file mounted into the container has the correct permissions for uid `1000`.
Example `docker run` command for SPIRE Server with non-root user configuration:

```bash
$ docker run \
    --user 1000:1000 \
    -p 8081:8081 \
    -v /path/to/server/config:/etc/spire/server \
    ghcr.io/spiffe/spire-server:1.6.1 \
    -config /etc/spire/server/server.conf
```

SPIRE plugin configuration may also depend on disk for various state and configuration.
The example configs do not cover every possible plugin dependency on a directory.
See [Directories-available-in-release-images](#directories-available-in-release-images) for natively supported directories that can be used for plugin data.

### (Advanced) Option 2) Use custom paths and/or specific non-root user in SPIRE configuration files

If you want to use configure SPIRE to use paths that are not used by the example configuration files, you can consider one or more of the following options based on your requirements:

1. Provide a volume/bind mount to the container at the desired path
1. Build your own custom container images based on the SPIRE release images with whatever customizations you may require.

If you want to run SPIRE as a non-root user that is not uid `1000`, you will need to build your own custom container images that set up permissions correctly for your dedicated user.

### Kubernetes environments

In Kubernetes, SPIRE Agent is normally deployed as DaemonSet to run one Workload API server instance per host, and it is necessary to inject the Workload API socket into each pod.
The [SPIFFE CSI Driver](https://github.com/spiffe/spiffe-csi) can be used to avoid the use of hostPath volumes in workload containers, but the use of a hostPath volume in the SPIRE Agent container is still needed.
For that reason, the SPIRE Agent container image is built to run as root by default.

## Directories available in release images

To address the previously mentioned limitations with scratch-based images, the SPIRE release images come with some commonly used directories pre-installed with correct permissions for a user with uid `1000` and group with gid `1000`.

### Common directories

* `/etc/spire`
* `/etc/ssl/certs`
* `/run/spire`
* `/var/lib/spire`

### SPIRE Server directories

These directories are all owned by `1000:1000`.

* `/etc/spire/server`
* `/run/spire/server/private`
* `/var/lib/spire/server`

### SPIRE Agent directories

These directories are all owned by `1000:1000`.

* `/etc/spire/agent`
* `/run/spire/agent/public`
* `/var/lib/spire/agent`
