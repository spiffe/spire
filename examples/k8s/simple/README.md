# Simple SPIRE deployment

This configuration is an example of a simple SPIRE deployment for Kubernetes.

+ The SPIRE [server](spire-server.yaml) runs as a StatefulSet using a
  PersistentVolume.
+ The SPIRE [agent](spire-agent.yaml) runs as a DaemonSet.

Both SPIRE agent and server run in the **spire** namespace, using service
accounts of **spire-server** and **spire-agent**.

## Usage

Set trust_domain and the cluster name for the k8s NodeAttestor. Additionally,
modify the path used in the *k8s-sa-cert* volume as appropriate for your
deployment - this is the certificate used to verify service accounts in the
SPIRE server.

Start the server StatefulSet:


```
$ kubectl apply -f spire-server.yaml
```

Start the agent DaemonSet:


```
$ kubectl apply -f spire-agent.yaml
```
