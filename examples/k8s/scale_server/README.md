# Scaling SPIRE server

## Configuration

There are a few important consideration when scaling out the number of SPIRE
servers for availability and resiliency.

### Database Persistence

To scale the number of SPIRE servers, an external datasource must be used to
maintain shared state between servers. Currently, SPIRE supports using the
Postgres database.

### Topology

The SPIRE server can be deployed either stateless or stateful, however in
either case it's imperative to configure the server appropriately to handle
failures and scalability.

+ **stateless** - To run the SPIRE server stateless, the `UpstreamCA` plugin
  needs to be used, and `upstream_bundle = true` needs to be set. An example of
  this configuration is the [postgres example](../postgres).
+ **stateful** - To run the SPIRE server stateful, the directory specified in
  `data_dir` must be persistent, where a StatefulSet and PersistentVolumeClaim
  are used. The [simple sat example](../simple_sat) is a partial example of this
  configuration, missing Postgres for a datatore.

#### Stateless Configuration

In a stateless deployment, an external UpstreamCA is used and present in the
bundle for the certificate verification chain. With this mode of deployment,
any new server is trusted by SPIRE agents by verifying the certificate chain
back to the UpstreamCA.

Upstream CA Certificates should have a short TTL and be rotated to maintain
trust and security between the SPIRE agents and servers.

#### Stateful Configuration

In a stateful deployment, at least one server must always be running. As there
is no Upstream CA in the bundle, each SPIRE server self-signs and publishes it's
own CA certificate into the bundle. SPIRE agents cannot connect to new servers
until they have received an updated bundle from an existing, trusted server.

### Load Balancing

This configuration relies on a mid-tier load balancer to distribute SPIRE
agent connections across servers. The example configuration uses a Kubernetes
NodePort, however production deployments may wish to use an external load
balancer instead.

Outside of a connection error there are currently no controls in SPIRE agent
or server to recycle connections in an attempt to maintain balance across all
deployed servers.

## Deployment

There is no additional configuration required to scale up the number of SPIRE
servers - simply increase the replica count of the spire-server Deployment (or
StatefulSet) in the spire namespace.

As mentioned in the load balancing section, existing agents will not
automatically balance connections across newly started SPIRE servers.
