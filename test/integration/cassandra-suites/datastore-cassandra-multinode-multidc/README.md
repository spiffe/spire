# Multi-node Datastore Cassandra Tests

This suite tests the datastore on a Cassandra cluster with three nodes in three different datacenters. It is not perfectly
stable and is known to flake at times, likely due to incomplete truncation of the tables in the keyspace.