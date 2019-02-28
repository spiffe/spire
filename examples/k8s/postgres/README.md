# Postgres SPIRE deployment

This configuration is an example of a SPIRE deployment for Kubernetes using
Postgres as a datastore for the SPIRE server. This configuration provides
better resiliancy and allows for scaling up the number of SPIRE servers.

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

## Usage

Set trust_domain and the cluster name for the k8s NodeAttestor. Additionally,
modify the path used in the *k8s-sa-cert* volume as appropriate for your
deployment - this is the certificate used to verify service accounts in the
SPIRE server.

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
