# Cassandra datastore implementation
This is a proof-of-concept implementation of Apache Cassandra as a backing datastore for SPIRE server. It leverages Cassandra 5.0 and is not compatible with earlier versions of Cassandra due to heavily leveraging Storage-Attached Indexes to improve query performance. 

## Background
For more about the pluggable datastore experiment and design, see the [experimental plugin design document](../../../plugin/datastore/README.md). This document describes the reference plugin implementation for Cassandra, demonstrating the viability of pluggability in the datastore layer. 

### About Cassandra
Apache Cassandra is a write-optimized, masterless NoSQL distributed database based around a table and wide column storage model. Cassandra offers tunable consistency at the query level, allowing developers to determine how much performance they are willing to sacrifice for strong consistency. Most queries in Cassandra are executed at some level of eventual consistency. 

Cassandra shines in providing global availability with acceptable performance on both the write and read path. Unlike traditional relational databases, Cassandra does not use a master or leader as the write node. Instead, any node may act as the coordinator for a query, and ensures that the data is written to the right members of the cluster, or retrieved from the right members of the cluster. To learn more about Apache Cassandra's design, read [the Cassandra docs](https://cassandra.apache.org/_/cassandra-basics.html). Consistency is tunable on a per-connection or per-query level. Data is replicated across members in the cluster according to a configurable replication strategy defined in the keyspace.

### Why Cassandra for SPIRE?
SPIRE server deployments have long been limited in horizontal scalability by the need to have a Postgres or MySQL cluster that is reliable enough to not lose data. In those database systems, this means geo-replication can happen passively or actively, but one cluster member in one region globally must be the writer at all times. Failing over is an event that incures some amount of downtime, unless one is willing to lose data. 

Cassandra solves these problems by allowing SPIRE servers to horizontally scale a single trust domain across regions to an unparalleled level. Cassandra is not an easy database to learn, nor an easy database to operate, but it offers outstanding performance and scalability when properly understood and deployed. My hope in sharing this implementation with the SPIRE community is to demonstrate that evolution in the data storage layer in SPIRE is needed, and that it's possible. 

## Cassandra Schema
The SPIRE server schema for Apache Cassandra uses a number of tables to store data for various entities:
- `registered_entries`: holds information about entries and their attributes
- `registration_entry_events`: holds information about changes in entry state and the time it occured, used by the SPIRE server for caching.
- `attested_node_entries`: holds information about attested nodes and their attributes.
- `attested_node_entries_events`: holds information about changes in node state and the time it occured, used by the SPIRE server for caching.
- `bundles`: used to store information about bundles from federated trust domains.
- `ca_journals`: used to store information by the SPIRE server about its active metadata.
- `federated_trust_domains`: used to store information by the SPIRE server about federated trust domain relationships.
- `join_tokens`: used to store information by the SPIRE server about join tokens issued by the server for agents to join the trust domain.

Cassandra uses a non-relational model where data is denormalized and stored according to how clients will query the data. This means that inside these tables, each of them may store information about how to find other records in other tables in ways that would surprise a newcomer to Cassandra. Also, in many cases data is repeated across rows in a partition, or otherwise represented in several ways in the same row! Again, data in Cassandra is modeled by how the client will query it, which makes repetition of a piece of data often the best way to allow clients to query that data in various ways. 

### Storage-Attached Indexes
Cassandra 5.0 introduced support for Storage-Attached Indexing, which allows performant filtering on non-partition key columns across partitions in `SELECT` statements. SPIRE Server exposes a very expressive API for `List*` RPC calls allowing users to provide arbitrary filters for many entities, including `RegistrationEntries`, `AttestedNodes` and other entities. These filters support multi-field filtering on arbitrary user-provided values. The provided filter fields are `AND`ed together. Cassandra has historically struggled with these kinds of queries, but Storage-Attached Indexing allows for much more performant and effecient cross-partition queries on an indexed column. The Cassandra datastore plugin leverages these indexes to implement the user filtering. For more information on these indexes, see the [001-spire-schema.cql](../migrations/001-spire-schema.cql) file.

### Denormalization and indexing
WIP

## General Limitations
- Cassandra will not return records in an order according to their creation time across partitions. Expect that the Cassandra plugin will have unpredicatable return ordering in comparison with the SQL database plugin.
- Cassandra pagination does not significantly reduce load on the database, so use pagination only where it makes sense because of truly unrealistic result sets. Do not treat pagination as an optimization - it is not when using the Cassandra datastore.
- This plugin is WIP and has not yet been reported running at scale.

## Pagination

## Filtering

## Ordering

## Test suite progress
