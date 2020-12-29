# Datastore MySQL replication Suite

## Description

Test SPIRE Server is able to use a query a readonly database that is replicated from a master server and keep it updated.
The suite runs the following MySQL versions against the SQL datastore unit tests:

- 5.5
- 5.6
- 5.7
- 8.0

A special unit test binary is built from sources that targets the docker
containers running MySQL.
