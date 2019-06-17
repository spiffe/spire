# Base SAT k7e configuration for SPIRE in minikube

This is a base Kustomize configuration for SPIRE running in minikube using the
SAT attestor. This is also the base configuration from which all other
configurations in this set of examples is derived.

See the [parent README](../) for instructions on using this configuration.

**Warning:** These configurations currently use the `unstable` label for SPIRE
container images, as the demo from community day requires SPIRE 0.8 features.
