# Postgres SPIRE deployment

This configuration is an example of a SPIRE deployment for Kubernetes using
Postgres as a datastore for the SPIRE server. This configuration provides
better resiliency and allows for scaling up the number of SPIRE servers.

+ [postgres](spire-database.yaml) runs is a StatefulSet using a
  PersistentVolume.
+ The SPIRE [server](spire-server.yaml) runs as a stateless Deployment.
+ The SPIRE agent runs as a DaemonSet - note this configuration is a link to
  the [simple example](../simple/spire-agent.yaml).

Both SPIRE agent and server, along with postgres, run in the **spire**
namespace, using service accounts of **spire-database**, **spire-server**, and
**spire-agent**.

Compare the [simple server](../simple/spire-server.yaml) configuration with
this [postgres backed server](spire-server.yaml) to see the differences, which
consist of: a Deployment instead of a StatefulSet, a datastore plugin change,
an InitContainer that waits for postgres to be up, and removal of the
PersistentVolumeClaim.

The SPIRE server can be deployed either stateless or stateful, however in
either case it's imperative to configure the server appropriately to handle
failures and scalability.

+ **stateless** - To run the SPIRE server stateless, the `UpstreamCA` plugin
  needs to be used, and `upstream_bundle = true` needs to be set.
+ **stateful** - To run the SPIRE server stateful, the directory specified in
  `data_dir` must be persistent (such as in the [simple example](../simple)
  where a StatefulSet and PersistentVolumeClaim are used.

In this example deployment, the SPIRE server is stateless, using the example
[dummy upstream CA](../../conf/server).

One other **important note**: In a production environment it is very important
to use a highly available Postgres configuration, unlike this configuration
where there is only a single Postgres instance. Doing so is outside the scope
of this example - there are a number of ways to achieve this.

## Usage

### Configuration

+ Set trust_domain and the cluster name for the k8s NodeAttestor.
+ Modify the path in the *k8s-sa-cert* volume for SPIRE server as appropriate
  for your deployment - this is the certificate used to verify service accounts
  in the cluster. This example assumes minikube.
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
