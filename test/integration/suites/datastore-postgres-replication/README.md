# Datastore PostgreSQL Suite

## Description

Test that SPIRE Server is able to run a query in a readonly database that is replicated from a primary server, keeping it updated.
The suite runs the following PostgreSQL versions against the SQL datastore unit tests:

- 10.x (latest)
- 11.x (latest)
- 12.x (latest)

A special unit test binary is built from sources that targets the docker
containers running PostgreSQL.
