# Example Kubernetes Configurations

This directory contains some example Kubernetes configurations which are also
used in automated SPIRE systems tests.

+ [simple](simple) - This is a simple configuration that deploys SPIRE server
  as a StatefulSet and SPIRE agent as a DaemonSet.
+ [postgres](postgres) - This expands on the **simple** configuration by moving
  the SPIRE datastore into a Postgres StatefulSet. The SPIRE server can now be
  scaled to have multiple replicas.
