# Simple SPIRE deployment using PSAT node attestor

This configuration is an example of a simple SPIRE deployment for Kubernetes that uses [PSAT node attestor](../../../doc/plugin_server_nodeattestor_k8s_psat.md).

+ The SPIRE [server](spire-server.yaml) runs as a StatefulSet using a
  PersistentVolumeClaim.
+ The SPIRE [agent](spire-agent.yaml) runs as a DaemonSet.

Both SPIRE agent and server run in the **spire** namespace, using service
accounts of **spire-server** and **spire-agent**.

## Usage

### Configuration

+ Set trust_domain and the cluster name for the k8s PSAT NodeAttestor.
+ Modify the path in the *k8s-sa-cert* volume for SPIRE server as appropriate
  for your deployment - this is the certificate used to verify service accounts
  in the cluster. This example assumes minikube.

### Deployment

Start the server StatefulSet:

```
$ kubectl apply -f spire-server.yaml
```

Authorize SPIRE server to talk to k8s API server:

```
$ kubectl apply -f authorization.yaml
```

Start the agent DaemonSet:

```
$ kubectl apply -f spire-agent.yaml
```
