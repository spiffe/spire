# Scalability

A SPIRE deployment has the capacity to be changed in size or scale to accommodate a growing amount of workloads. A SPIRE deployment is composed of a number of one or more SPIRE Servers that share a replicated datastore, or conversely, a set of SPIRE servers in the same trust domain, and at least one SPIRE Agent, but typically more than one.

Deployments range in size. A single SPIRE Server may accommodate a number of Agents and Workload Registration entries. A scale sizing consideration is that the memory and CPU consumption of SPIRE Server instances tends to grow proportionally to the number of Workload Registration entries in a deployment due to the number of operations involved in managing and issuing identities corresponding to those entries, . A single instance of a SPIRE Server also represents a single point of failure.

To support larger numbers of Agents and Workloads within a given deployment (tens of thousands or hundreds of thousands of nodes), the number of SPIRE Servers can be scaled horizontally. With multiple servers, the amount of computational work that a SPIRE Server performs is distributed between all SPIRE Server instances. In addition to additional capacity, the use of more than one SPIRE Server instance eliminates single points of failure to achieve high availability.

## SPIRE Servers in High Availability Mode

![Diagram of High Availability](/doc/images/ha_mode.png)

To scale the SPIRE Server horizontally, be it for high availability or load distribution purposes, configure all servers in same trust domain to read and write to the same shared datastore.

The datastore is where SPIRE Server persists dynamic configuration information such as registration entries and identity mapping policies. SQLite is bundled with SPIRE Server and it is the default datastore. A number of compatible SQL databases are supported, as well as one plugin for Kubernetes using Kubernetes CRDs. When scaling SPIRE servers horizontally, choose a datastore that fits your requirements and configure all SPIRE servers to use the selected datastore. For details please refer to the [datastore plugin configuration reference](https://github.com/spiffe/spire/blob/master/doc/plugin_server_datastore_sql.md).

In High Availability mode, each server maintains its own Certificate Authority, which may be either self-signed certificates or an intermediate certificate off of a shared root authority (i.e. when configured with an UpstreamAuthority).

# Choosing a SPIRE Deployment Topology

There are three main SPIRE deployment topologies:

* Single trust domain
* Nested SPIRE
* Federated SPIRE

Factors such as administrative domain boundaries, number of workloads, availability requirements, number of cloud vendors, and authentication requirements determine the appropriate topology for your environment, as explained below.

## Single Trust Domain

![Diagram of Single Trust Domain](/doc/images/single_trust_domain.png)

A single trust domain is best suited for individual environments or environments that share similar characteristics within an administrative domain. The primary motivation for a single overarching trust domain is to issue identities from a single Certificate Authority, as it reduces the number of SPIRE Servers in distinct deployments to manage.

However, when deploying a single SPIRE trust domain to span regions, platforms, and cloud provider environments, there is a level of complexity associated with managing a shared datastore across geographically dispersed locations or across cloud provider boundaries. Under these circumstances when a deployment grows to span multiple environments, a solution to address the use of a shared datastore over a single trust domain is to configure SPIRE Servers in a nested topology.

## Nested SPIRE


![Diagram of Nested SPIRE](/doc/images/nested_spire.png)

Nested SPIRE allows SPIRE Servers to be “chained” together, and for all servers to still issue identities in the same trust domain, meaning all Workloads identified in the same trust domain are issued identity documents that can be verified against the root keys of the trust domain.

Nested topologies works by co-locating a SPIRE Agent with every downstream SPIRE Servers being “chained”. The downstream SPIRE Server obtains credentials over the Workload API that it uses to directly authenticate with the upstream SPIRE Server to obtain an intermediate CA.

A mental model that helps understand the functionality of Nested topologies is to think about the top-level SPIRE Server as being a global server (or set of servers for high availability), and downstream SPIRE Servers as regional or cluster level servers.

In this configuration, the top tier SPIRE Servers hold the root certificate/key, and the downstream servers request an intermediate signing certificate to use as the downstream server's X.509 signing authority. It provides for resilience as the top tier can go down, and intermediate servers will continue to operate.

The Nested topology is well suited for multi-cloud deployments. Due to the ability to mix and match node attestors, the downstream servers can reside and provide identities for Workloads and Agents in different cloud provider environments.

Complementary to scaling SPIRE Servers horizontally for high availability and load-balancing, a nested topology may be used as a containment strategy to segment failure domains.

## Federated SPIRE

![Diagram of Federated SPIRE](/doc/images/federated_spire.png)

Deployments may require multiple roots of trust: perhaps because an organization has different organizational divisions with different administrators, or because they have separate staging and production environments that occasionally need to communicate.

Another use case is SPIFFE interoperability between organizations, such as between a cloud provider and its customers.

These multiple trust domain and interoperability use cases both require a well-defined, interoperable method for a Workload in one trust domain to authenticate a Workload in a different trust domain. Trust between the different trust domains is established by first authenticating the respective bundle endpoint, followed by retrieval of the foreign trust domain bundle via the authenticated endpoint.

For additional detail on how this is achieved, refer to the following SPIFFE spec that describes the mechanism: https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md#5-spiffe-bundle-endpoint

# Interaction with External Systems

## Federation with "SPIFFE-Compatible" Systems

![Diagram of Federated with SPIFFE-Compatible Systems](/doc/images/spiffe_compatible.png)

SPIFFE identity issuers can federate with other SPIFFE identity issuers that expose an implementation of the SPIFFE Federation API, enabling Workloads in federated domains to securely authenticate and communicate. Much like federation between SPIRE deployments, SPIFFE Federation is used to enable federation between SPIFFE-compatible systems, say between a SPIRE deployment and an Istio service mesh, or an Istio service mesh running in one cluster in one datacenter to another Istio service mesh running elsewhere.

For example, in current Istio, all applications on the service mesh are in the same trust domain thus share a common root of trust. There may be more than one service mesh, or applications in the service mesh communicating to external services that need to be authenticated. The use of Federation enables SPIFFE-compatible systems such as multiple Istio service meshes to securely establish trust for secure cross-mesh and off-mesh communications.

## Federation with OIDC-Provider Systems

![Diagram of Federated with SPIFFE-Compatible Systems](/doc/images/oidc_federation.png)

SPIRE has a feature to programmatically authenticate on behalf of identified workloads to remote systems such as public cloud provider services and secret stores that are OIDC-Federation compatible.  For example, in the case of Amazon Web Services, a SPIRE identified workload can authenticate and communicate with an AWS S3 Bucket, an AWS RDS instance, or AWS CodePipeline.

The SPIRE OIDC Discovery Provider retrieves a WebPKI certificate using the ACME protocol, which it uses to secure an endpoint that serves an OIDC compatible JWKS bundle and a standard OIDC discovery document. The remote OIDC authenticated service needs then to be configured to locate the endpoint and qualify the WebPKI service.   Once this configuration is in place, the remote system’s IAM policies and roles can be set to map to specific SPIFFE IDs.  The workload, in turn, will talk to the OIDC-authenticated system by sending a JWT-SVID.  The target system then fetches a JWKS from the pre-defined URI which is served by the OIDC Discovery Provider.  The target system uses the JWKS file to validate the  JWT-SVID, and if the SPIFFE ID contained within the JWT-SVID is authorized to access the requested resource, it serves the request.  The workload is then able to access the foreign remote service without possessing any credentials provided by it.

For a configuration reference on the OIDC Discovery Provider, see:
https://github.com/spiffe/spire/tree/master/support/oidc-discovery-provider

For a detailed tutorial on configuring OIDC Federation to Amazon Web Services, refer to: https://spiffe.io/spire/try/oidc-federation-aws/

# Deployment Sizing Considerations

Factors to consider when sizing a SPIRE deployment for optimum performance include, but are not limited to, the following:

* SVID and root certificate TTLs
* Number and distribution of Workloads per node
* Heavy JWT-SVID use (because JWTs must be signed as needed, rather than pre-stashed like x509s)
* Frequency of registration changes
* Other processes running on a SPIRE Server node
* “Shape” and “size” of the underlying infrastructure environment

Particular emphasis is to be given to datastore design and planning.  Note that datastore performance is not addressed in the list above, and can potentially limit SPIRE performance. The datastore has shown in general to be the biggest performance bottleneck since the authorization checks that happen per-agent sync (once every 5 seconds per-agent) are relatively expensive. This cost can be reduced in nested topologies since each SPIRE server cluster in the nested topology has its own datastore.

The following table is intended to provide a reference for sizing SPIRE Servers in SPIRE deployments. These reference numbers are based on a test environment. They are meant as order-of-magnitude guidelines only and do not represent a performance guarantee for any particular user environment. Network bandwidth and database query information is not included. Also, the number of Workloads and Agents shown do not represent the theoretically possible SPIRE deployment scale.

| Number of Workloads | 10 Agents                                             | 100 Agents                                            | 1000 Agents                                          | 5000 Agents                                           |
|---------------------|------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|
| 10 Workloads        | 2 Server Units with 1 CPU core, 1GB RAM              | 2 Server Units with 2 CPU cores, 2GB RAM             | 2 Server Units with 4 CPU cores, 4GB RAM             | 2 Server Units with 8 CPU cores, 8 GB RAM            |
| 100 Workloads       | 2 Server Units with 2 CPU cores, 2GB RAM             | 2 Server Units with 2 CPU cores, 2GB RAM             | 2 Server Units with 8 CPU cores, 8 GB RAM            | 2 Server Units with 16 CPU cores, 16 GB RAM          |
| 1,000 Workloads     | 2 Server units with 16 CPU Cores, and 8GB RAM        | 2 Server units with 16 CPU Cores, and 8GB RAM        | 2 Server units with 16 CPU Cores, and 8GB RAM        | 4 Server units with 16 CPU Cores, and 8GB RAM        |
| 10,000 Workloads    | 4 Server units with 16 CPU Cores each, and 16 GB RAM | 4 Server units with 16 CPU Cores each, and 16 GB RAM | 4 Server units with 16 CPU Cores each, and 16 GB RAM | 8 Server units with 16 CPU Cores each, and 16 GB RAM |
