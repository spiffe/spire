# Postgres SPIRE deployment

This configuration is an example of a SPIRE deployment for Kubernetes using
Postgres as a datastore for the SPIRE server. This configuration provides
better resiliency and allows for scaling up the number of SPIRE servers.

+ [postgres](spire-database.yaml) runs as a StatefulSet using a
  PersistentVolume.
+ The SPIRE [server](spire-server.yaml) runs as a stateless Deployment.
+ The SPIRE agent runs as a DaemonSet - note this configuration is a symlink
  to the [simple sat example](../simple_sat/spire-agent.yaml).

Both SPIRE agent and server, along with postgres, run in the **spire**
namespace, using service accounts of **spire-database**, **spire-server**, and
**spire-agent**.

Compare the [simple sat server](../simple_sat/spire-server.yaml) configuration with
this [postgres backed server](spire-server.yaml) to see the differences, which
consist of: a Deployment instead of a StatefulSet, a datastore plugin change,
an InitContainer that waits for postgres to be up, and removal of the
PersistentVolumeClaim.

The SPIRE server can be deployed either stateless or stateful, however in
either case it's imperative to configure the server appropriately to handle
failures and scalability.

+ **stateless** - To run the SPIRE server stateless (as in this example), the
  `UpstreamCA` plugin needs to be used, and `upstream_bundle = true` needs to
  be set.
+ **stateful** - To run the SPIRE server stateful, the directory specified in
  `data_dir` must be persistent (such as in the [simple sat example](../simple_sat)
  where a StatefulSet and PersistentVolumeClaim are used.

In this example deployment, the SPIRE server is stateless, using the example
[dummy upstream CA](../../../conf/server).

One other **important note**: In a production environment it is very important
to use a highly available Postgres configuration, unlike this configuration
where there is only a single Postgres instance. Doing so is outside the scope
of this example - there are a number of ways to achieve this.

## Usage

### Configuration

+ Set trust_domain and the cluster name for the k8s NodeAttestor.
+ Replace `MYSECRET` in both **spire-database.yaml** and **spire-server.yaml**.
  This is the password for the Postgres account used by the SPIRE server's
  datastore.

### Deployment

Start the postgres StatefulSet:

```
$ kubectl apply -f spire-database.yaml
```

Start the server Deployment:

```
$ kubectl apply -f spire-server.yaml
```

Start the agent DaemonSet:

```
$ kubectl apply -f spire-agent.yaml
```
