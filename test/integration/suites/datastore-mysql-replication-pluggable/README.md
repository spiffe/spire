# Datastore MySQL replication Suite

## Description

Test that SPIRE Server is able to run a query in a readonly database that is replicated from a primary server, keeping it updated.
The suite runs the following MySQL versions against the SQL datastore unit tests:

- 5.7
- 8.0

A special unit test binary is built from source, targeting the docker
containers running MySQL.
