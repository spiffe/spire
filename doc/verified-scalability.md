

# Scalability

A SPIRE deployment is composed of one or more SPIRE Servers (replicated with shared datastore) and one or more SPIRE Agents. On a single SPIRE server per SPIRE deployment, memory and CPU usage tends to grow proportionally with size/load on cluster. To support very large numbers of agents within a given trust domain (tens of thousands or hundreds of thousands of nodes), SPIRE servers can be scaled horizontally. With multiple servers, the load is distributed. In addition to capacity, the use of more than one SPIRE server also eliminates a single point of failure and attains high availability.

This table contains verified scalability of SPIRE deployments using a combination of number of workloads across a number of nodes (1 agent per node), and corresponding SPIRE Server sizing recommendations. These numbers are intended to serve as sample guidance, are not representative of upper bound scale limits nor configuration maximums. These numbers do not represent the theoretically possible SPIRE deployment scale.

| ﻿Number of Workloads | 10 Agents                                             | 100 Agents                                            | 1000 Agents                                          | 5000 Agents                                           |
|---------------------|------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|
| 10 Workloads        | 2 Server Units with 1 CPU core, 1GB RAM              | 2 Server Units with 2 CPU cores, 2GB RAM             | 2 Server Units with 4 CPU cores, 4GB RAM             | 2 Server Units with 8 CPU cores, 8 GB RAM            |
| 100 Workloads       | 2 Server Units with 2 CPU cores, 2GB RAM             | 2 Server Units with 2 CPU cores, 2GB RAM             | 2 Server Units with 8 CPU cores, 8 GB RAM            | 2 Server Units with 16 CPU cores, 16 GB RAM          |
| 1,000 Workloads     | 2 Server units with 16 CPU Cores, and 8GB RAM        | 2 Server units with 16 CPU Cores, and 8GB RAM        | 2 Server units with 16 CPU Cores, and 8GB RAM        | 4 Server units with 16 CPU Cores, and 8GB RAM        |
| 10,000 Workloads    | 4 Server units with 16 CPU Cores each, and 16 GB RAM | 4 Server units with 16 CPU Cores each, and 16 GB RAM | 4 Server units with 16 CPU Cores each, and 16 GB RAM | 8 Server units with 16 CPU Cores each, and 16 GB RAM |

