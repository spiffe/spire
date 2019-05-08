# Simple SPIRE deployment using SAT node attestor

This configuration is an example of a simple SPIRE deployment for Kubernetes that uses [SAT node attestor](../../../doc/plugin_server_nodeattestor_k8s_sat.md).

+ The SPIRE [server](spire-server.yaml) runs as a StatefulSet using a
  PersistentVolumeClaim.
+ The SPIRE [agent](spire-agent.yaml) runs as a DaemonSet.

Both SPIRE agent and server run in the **spire** namespace, using service
accounts of **spire-server** and **spire-agent**.
Also RBAC authorization policies are set in order to guarantee access to certain resources.

## Usage
_This example can be run in minikube and EKS. Read the [considerations](#considerations)_

### Configuration

+ Set trust_domain and the cluster name for the k8s SAT NodeAttestor.
+ Modify the path in the k8s-sa-cert volume for SPIRE server as appropriate for your deployment - this is the certificate used to verify service accounts in the cluster. This example assumes minikube.

### Deployment

Start the server StatefulSet:

```
$ kubectl apply -f spire-server.yaml
```

Start the agent DaemonSet:

```
$ kubectl apply -f spire-agent.yaml
```

## Considerations
### Running this example in minikube
No special considerations must be taken into account for running this example in minikube.

### Running this example in EKS
Some changes has been recently made to SAT attestor to make it compatible with kubernetes managed enviroments. A certificate is not
longer requiered in SPIRE server configuration to validate the service account token. Instead, the kubernetes Token Review API is used.
The following changes must be applied to the files before deploying this example in EKS:

#### Update SPIRE image
*Since this update has not been released yet, the `unstable` image must be used.*

+ Replace the current image in the [server configuration file](spire-server.yaml):
```
image: gcr.io/spiffe-io/spire-server:0.7.3
```
with

```
image: gcr.io/spiffe-io/spire-server:unstable
```

+ Replace the current image in the [agent configuration file](spire-agent.yaml):
```
image: gcr.io/spiffe-io/spire-agent:0.7.3
```
with
```
image: gcr.io/spiffe-io/spire-agent:unstable
```

#### Remove volume for certificate
*Remove the volume for the certificate used to validate the token, it is not longer required.*

+ Remove the volume from the [server configuration file](spire-server.yaml):
```
...
        - name: k8s-sa-cert
          hostPath:
            path: /var/lib/minikube/certs/sa.pub
            type: File
...
```
+ Remove the volume mount from the [server configuration file](spire-server.yaml):
```
...
        - name: k8s-sa-cert
            mountPath: /run/k8s-certs/sa.pub
            readOnly: true
...
```

+ Remove the `service_account_key_file` configuration form SAT node attestor in the [server configuration file](spire-server.yaml):
```
...
service_account_key_file = "/run/k8s-certs/sa.pub"
...
```