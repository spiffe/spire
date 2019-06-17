# Example Kubernetes Configurations

This directory contains some example Kubernetes configurations which are also
used in automated SPIRE systems tests.

+ [simple sat](simple_sat) - This is a simple configuration using the Kubernetes
  [service account token (SAT) attestor](../../doc/plugin_server_nodeattestor_k8s_sat.md)
  that deploys SPIRE server as a StatefulSet and SPIRE agent as a DaemonSet.
+ [simple psat](simple_psat) - This is a simple configuration using the
  Kubernetes
  [projected service account token (PSAT) attestor](../../doc/plugin_server_nodeattestor_k8s_psat.md)
  that otherwise deploys SPIRE as in the **simple sat** example.
+ [postgres](postgres) - This expands on the **simple sat** configuration by
  moving the SPIRE datastore into a Postgres StatefulSet. The SPIRE server is
  now a stateless Deployment that can be scaled.
+ [eks sat](eks_sat) - This slightly modifies the **simple sat** configuration to
  make it compatible with EKS platform.
+ [k7e](k7e) - A set of SPIRE examples using [Kustomize](https://kustomize.io/)
  as shown at the SPIFFE Community Day in May, 2019.
