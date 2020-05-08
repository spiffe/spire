# Scalability

A SPIRE deployment is composed of a number one or more SPIRE Servers that share a replicated datastore, and one or more SPIRE Agents. With only one SPIRE Server per SPIRE deployment, the memory and CPU usage tends to grow proportionally with the number of workloads in the deployment. To support very large numbers of workloads and agents within a given trust domain (tens of thousands or hundreds of thousands of nodes), the number of SPIRE Servers can be scaled horizontally. With multiple servers, the load is distributed. In addition to capacity, multiple SPIRE Servers can be configured for high availability.

It is important to note when scaling the number servers horizontally, be it for high availability or load distribution purposes, that in any configuration of two or more SPIRE Servers, all servers share the same datastore. Each server maintains its own CA however, which may be self-signed or an intermediate off of a shared root authority (i.e. when configured with an UpstreamAuthority).

# Topologies

There are three main SPIRE deployment topologies; single trust domain, nested SPIRE, and federated SPIRE. Multiple factors should be considered when choosing one topology design over another.

A common motivation for a single overarching trust domain is to issue identities from a single Certificate Authority, as it reduces the number of components to manage. However, when deploying a single SPIRE trust domain to span regions, platforms, and cloud provider environments, there is a level of complexity associated with managing a shared datastore across geographically dispersed locations or across cloud provider boundaries. Under these circumstances a solution to address the use of a shared datastore is to configure SPIRE Servers in a nested topology.

## Nested SPIRE

Nested SPIRE allows SPIRE Servers to be chained together, and for all servers to still issue identities in the same trust domain. It works by co-locating an agent with downstream servers. The downstream SPIRE Server obtains credentials over the Workload API that it uses to directly authenticate with the upstream SPIRE Server to obtain an intermediate CA. 
 
This topology is well suited for multi-cloud deployments. It can be reasoned as the top server being a global server (or set of servers for high availability). The downstream servers may be deployed at either regional or cluster level. Due to the ability to mix and match node attestors, the downstream servers can reside in different clouds. 
 
In this configuration, the top tier SPIRE Servers hold the root certificate/key, and the downstream servers request an intermediate signing certificate to use as the server's X.509 signing authority. It provides for resilience as the top tier can go down, and intermediate servers will continue to operate. 
 
Complimentary to scaling SPIRE Servers horizontally to deal with load, a nested topology helps to segment failure domains.

## Federated SPIRE

A requirement or objective may exist to make use of multiple roots of trust: perhaps because an organization has different organizational divisions with different administrators, or because they have separate staging and production environments that occasionally need to communicate. A similar use-case is SPIFFE interoperability between organizations, such as between a cloud provider and its customers. Both use-cases require a well-defined, interoperable method for a workload in one trust domain to authenticate a workload in a different trust domain.
Trust between the different trust domains is established by first authenticating the respective bundle endpoint, followed by retrieval of the foreign trust domain bundle via the authenticated endpoint. For additional detail on how this is achieved, refer to the following SPIFFE spec that describe the mechanism: 
https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md#5-spiffe-bundle-endpoint

# Cluster Sizing Considerations

This table provides a reference for sizing SPIRE Servers in SPIRE deployments. These reference numbers are based off a test environment. They are meant as order-of-magnitude guidelines only, and do not represent a performance guarantee for any particular user environment.  Also, the number of workloads and agents shown do not represent the theoretically possible SPIRE deployment scale. Note that datastore performance is not addressed here, and can potentially limit SPIRE performance. There are many factors that will influence SPIRE performance including, but not limited to:

* SVID and root certificate TTLs
* Number and distribution of workloads per node
* Heavy JWT-SVID use (because JWTs must be signed as needed, rather than pre-stashed like x509s)
* Frequency of registration changes
* Other processes running on a SPIRE Server node

The datastore has shown in general to be the biggest performance bottleneck since the authorization checks that happen per-agent sync (which happens once every 5 seconds per agent)  are relatively expensive. This cost can be reduced in nested topologies, since each SPIRE server cluster in the nested topology has its own datastore.


| Number of Workloads | 10 Agents                                             | 100 Agents                                            | 1000 Agents                                          | 5000 Agents                                           |
|---------------------|------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|
| 10 Workloads        | 2 Server Units with 1 CPU core, 1GB RAM              | 2 Server Units with 2 CPU cores, 2GB RAM             | 2 Server Units with 4 CPU cores, 4GB RAM             | 2 Server Units with 8 CPU cores, 8 GB RAM            |
| 100 Workloads       | 2 Server Units with 2 CPU cores, 2GB RAM             | 2 Server Units with 2 CPU cores, 2GB RAM             | 2 Server Units with 8 CPU cores, 8 GB RAM            | 2 Server Units with 16 CPU cores, 16 GB RAM          |
| 1,000 Workloads     | 2 Server units with 16 CPU Cores, and 8GB RAM        | 2 Server units with 16 CPU Cores, and 8GB RAM        | 2 Server units with 16 CPU Cores, and 8GB RAM        | 4 Server units with 16 CPU Cores, and 8GB RAM        |
| 10,000 Workloads    | 4 Server units with 16 CPU Cores each, and 16 GB RAM | 4 Server units with 16 CPU Cores each, and 16 GB RAM | 4 Server units with 16 CPU Cores each, and 16 GB RAM | 8 Server units with 16 CPU Cores each, and 16 GB RAM |
