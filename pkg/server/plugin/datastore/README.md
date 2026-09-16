# Pluggable Datastore Design
This is a proof-of-concept implementation of supporting datastore plugins in the SPIRE server. It makes core changes to `spire` and `spire-plugin-sdk` to support "pluggability" of the datastore. Included is a prototype reference implementation using Apache Cassandra as a backing datastore for SPIRE server. It leverages Cassandra 5.0 and is not compatible with earlier versions of Cassandra due to heavily leveraging Storage-Attached Indexes to improve query performance. 

## Background
There have been frequent requests from the community to support customizations to the SPIRE Server storage layer, including support for additional databases and other customizations that introduce maintance burden and increase core project complexity. In other issues, changes to the datastore architecture are discussed as potential solutions to various scalability, reliability or availability problems. Some examples include:
- https://github.com/spiffe/spire/issues/5993: Requested support for Apache Cassandra (my own feature request that spawned this project)
- https://github.com/spiffe/spire/issues/5624: Using CDC with SQL to build the event-based cache
- https://github.com/spiffe/spire/issues/5501#issuecomment-3765754948: supporting larger primary key ID ranges in large scale deployments
- https://github.com/spiffe/spire/issues/5113: discussion of rotation of database credentials
- https://github.com/spiffe/spire/issues/2664: support for HA Databases via dqlite or cowsql
- https://github.com/spiffe/spire/issues/5854: support for GaussDB
- https://github.com/spiffe/spire/issues/4968: customizations to database authentication to use X509-SVIDs as authentication material
- https://github.com/spiffe/spire/issues/4992: using a multi-primary database architecture
- https://github.com/spiffe/spire/issues/4212: client certificate authentication with SPIRE-generated certificates for the database
- https://github.com/spiffe/spire/issues/1945: support for pluggable KV and SQL stores, mentioning etcd. This issue involved a full redesign of the data storage interface and was closed due to complexity.
- https://github.com/spiffe/spire/issues/1218: support for disabling auto-migrations and allowing users to migrate the database schema manually via an out-of-band process
- https://github.com/spiffe/spire/issues/1830: prototyping for using the now-defunct Cayley project for pluggability

Based on these issues, it is clear to me that providing some mechanism to extend the data storage layer without requiring fully custom builds of the SPIRE server binary or container would be useful. Extensionability allows advanced users to make customizations that _they themselves are responsible for understanding, verifying, and supporting_. This model has made SPIRE extremely successful for supporting various Node or Workload attestation strategies, and the success of these safety and correctness-critical plugin subsystems demonstrate that even the most sensitive features of SPIRE like attestation benefit from a generic extensionability model.

If a user today wants to customize the datastore implementation, they effectively have two options:
- fork and build SPIRE from source, introducing long-term maintance burden and overhead to sustain that fork, keep it up-to-date and verify no regressions in core functionality, etc.
- propose a change to the existing core datastore, which places the burden on SPIRE maintainers to understand and develop expertise in whatever storage architecture the user would like to use. Rightfully so, this means that many proposed datastore changes do not get made, because the complexity of maintaining and assuring the safety and correctness of many different implementations is an unreasonable burden to place on a small maintainer pool.

Extending the SPIRE storage layer to support plugins strikes a balance between user extensibility and maintainer burden: users are free to extend the datastore as they would like, while taking on full responsibility for supportability, reliability and performance. Maintainers continue to own the core SPIRE Datastore interface layer, and support the SQL implementation currently available in the SPIRE Server. The Datastore interface can evolve along with the needs of the SPIRE project, and users will manage ensuring that their plugin implementations are up to date. Once this model is proven and mature, if desired, it may be more beneficial to consider changes to the core storage system to further reduce the maintance burden and decrease the likelyhood of breaking changes in the SPIRE server cascading to experimental plugins. There is, however, no need to do this to accomplish basic pluggability.

This document describes the implementation decisions to support pluggability of the SPIRE datastore, using Apache Cassandra as a reference implementation. 

### About Cassandra
Apache Cassandra is a write-optimized, masterless NoSQL distributed database based around a table and wide column storage model. Cassandra offers tunable consistency at the query level, allowing developers to determine how much performance they are willing to sacrifice for strong consistency. Most queries in Cassandra are executed at some level of eventual consistency. 

Cassandra shines in providing global availability with acceptable performance on both the write and read path. Unlike traditional relational databases, Cassandra does not use a master or leader as the write node. Instead, any node may act as the coordinator for a query, and ensures that the data is written to the right members of the cluster, or retrieved from the right members of the cluster. To learn more about Apache Cassandra's design, read [the Cassandra docs](https://cassandra.apache.org/_/cassandra-basics.html).

### Why Cassandra for SPIRE?
SPIRE server deployments have long been limited in horizontal scalability by the need to have a Postgres or MySQL cluster that is reliable enough to not lose data. In those database systems, this means geo-replication can happen passively or actively, but one cluster member in one region globally must be the writer at all times. Failing over is an event that incures some amount of downtime, unless one is willing to lose data. 

Cassandra solves these problems by allowing SPIRE servers to horizontally scale a single trust domain across regions to an unparalleled level. Cassandra is not an easy database to learn, nor an easy database to operate, but it offers outstanding performance and scalability when properly understood and deployed. My hope in sharing this implementation with the SPIRE community is to demonstrate that evolution in the data storage layer in SPIRE is needed, and that it's possible. To see more about the Cassandra plugin implemented to prove the viability of a pluggable datastore, see [the plugin design document](../../datastore/cassandra/design/README.md).

## Design notes
The SPIRE server defines [a `Datastore` interface](https://github.com/spiffe/spire/blob/main/pkg/server/datastore/datastore.go) for data storage interactions. This package also contains a number of types for use by the SPIRE server client code when interacting with the interface, including various filters, request and response types, etc. The `datastore` package also contains a simple `Repository` type with accessor and setter methods for the datastore. The `datastore.Repository` is not used in the project and seems to be a historical artifact of previous implementation requirements that were refactored away over time. 

SPIRE Server currently has three implementations of the `datastore.Datastore` interface:
- The `sqlstore` [implementation](https://github.com/spiffe/spire/tree/main/pkg/server/datastore/sqlstore), currently the only supported datastore.
- The `pkg/common/server/datastore/` `metricsWrapper` [implementation wrapping calls to the Datastore with metrics collection](https://github.com/spiffe/spire/blob/main/pkg/common/telemetry/server/datastore/wrapper.go)
- The `test/fakes/fakedatastore` `fakeDatastore` [implementation for unit tests](https://github.com/spiffe/spire/blob/main/test/fakes/fakedatastore/fakedatastore.go). 

### The `sqlstore` implementation
The existing `Datastore` implementation is provided by the `sqlstore` package. This package uses `gorm` to wrap the underlying database, providing support for sqlite, MySQL, and Postgresql. The interface methods are implemented by the `sqlstore` package but generally delegate to private, unexported helper methods that contain the majority of the business logic. The `sqlstore` package heavily leverages transations to achieve consistency. 

### Supporting pluggability in the Datastore
A goal of this project was to explore the viability of reintroducing plugin support for the datastore used by the SPIRE server at runtime. This is not easy, as the `datastore.Datastore` interface used throughout the codebase has 56 methods and uses a mixture of its own types and other imported types in its interface. To avoid a massive distruptive refactor, I decided to leave the existing `datastore.Datastore` interface almost fully intact, with [minimal changes](#changes-made-to-the-datastore-code) made to support treating the `datastore.Datastore` interface as a plugin. 

#### `spire-api-sdk` changes
I added a `spire.plugin.server.datastore.v1alpha1` package to the `spire-api-sdk` repository. The existing API packages defined in this repository are all `v1`, and I was unable to find an example of how the SPIRE maintainers manage alpha/experimental APIs, so I followed a common Kubernetes convention. The `v1alpha1` package is large and defines a contract for implementing a datastore plugin, as well as API types for representing the types that the SPIRE server `datastore.Datastore` interface uses. This is purely a proof of concept API and deserves better documentation and scrutiny.

The `datastorev1alpha1.Datastore` service exposes most of the same methods that the `datastore.Datastore` interface exposes. Each RPC takes a distinct `Request` message and returns a distinct `Response` message:
```proto3
rpc AppendBundle(AppendBundleRequest) returns (AppendBundleResponse);
```

#### Type conversions and facade implementation
To be utilized by the SPIRE server, these types must be converted from the wire types to the types used by the `datastore.Datastore` interface. This is performed by a facade implementation, which uses a set of conversion helpers to transform each input called on the `datastore.Datastore` interface that it implements to the corresponding `datastorev1alpha1` `Request` message. Responses are then translated to the `datastore.Datastore` interface types with similar helpers. This is not the most resource-effecient way to implement this, because it introduces a per-call overhead of at least two struct initializations and corresponding wire marshalling/unmarshalling. This will require analysis and improvement over time. For now, simply expect the SPIRE server to use more memory and perform many more allocs than it does currently.

#### Server catalog `dataStoreRepository`
A simple repository for the datastore was added, following the pattern for other plugin repositories. The datastore repository utilizes a `MaybeOne` constraint, and currently only provides the Cassandra plugin as a builtin. To mature this implementation, it would be useful to implement an additional builtin plugin, perhaps for etcd as discussed in https://github.com/spiffe/spire/issues/1945.

#### Server catalog `ExperimentalConfig` and loading
An `ExperimentalConfig` type was added to the `pkg/server/catalog` package to allow plumbing of the experimental config option into the catalog. When the `AllowPluggableDatastore` field is set to `true`, the catalog will initialize the datastore plugin `dataStoreRepository` as a plugin repository. During `Load()` the catalog will avoid stripping the datastore configuration from other plugin configuration, and instead delegate it to the common catalog's `Load()` process. If not set, the existing code paths will be executed to strip the datastore configuration from other plugin configuration, load the SQL datastore with `loadSQLDataStore()`, and then statically set the datastore in the repository before continuing with the common catalog `Load()` process for the other plugins.

#### Per-plugin `max_grpc_message_size` configuration option
An optional configuration field called `max_grpc_message_size` was added to the `catalog.hclPluginConfig` type. This field can be used to provide an `int` representing the maximum gRPC message size to send/receive with a plugin. This field applies to both builtin and external plugins. If not set, this field defaults to the standard 4MB gRPC maximum message size limit. This field was added due to historical context surrounding the original datastore plugin interface that mentioned issues with max message size limits breaking RPC calls to the plugin due to resource exhaustion (see https://github.com/spiffe/spire/pull/1938).

### Changes made to the Datastore code
A number of changes were made to the datastore code, some for clarity and conciseness, some for testability, and others because changes were required to make this POC possible.

- The `testdata` originally stored in `pkg/server/datastore/sqlstore/testdata` has been moved into an importable package leveraging Go's embedded files functionality so that the testdata can be used by multiple plugins to test the behavior of the interface contract. _This change is for conciseness and testability._
- In the spirit of preserving the original `datastore.Datastore` interface throughout the codebase, some additional methods were added to the `datastore.Datastore` interface to support using this interface when loaded as a plugin. These include the methods listed below, and these were implemented in the three existing `datastore.Datastore` interface implementations. _These changes were **required** to support pluggability in the Datastore without requiring a major refactor to the rest of the SPIRE server code._
  - `func Name() string`: added to provide the name of the datastore when loaded as a plugin by implementing the `catalog.PluginInfo` interface LINK!!!!
  - `func Type() string`: added to provide the type of the datastore implementation when loaded as a plugin.
  - `func Close() error`: added to allow the datastore to be closed when loaded as a plugin.
  - `func Configure (context.Context, *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error)`: added to allow the datastore to receive configuration via the standard plugin catalog loader code. This code is now used by the `dsConfigurer` type, instead of the previous wrapper methods.
  - `func Validate (context.Context, *configv1.ValidateRequest) (*configv1.ValidateResponse, error)`: added to allow the datastore configuration to be validated via the standard plugin catalog loader clode. This code is also now used by the `dsConfigurer` type.
- The `datastore.Repository` type referenced in [the introduction](#design-notes) was deleted to avoid confusion between it and the new catalog `datastoreRepository`.

Additional changes could be made to reduce the duplication and potential maintenance burden if this experimental feature is considered for inclusion:
- The `sqlstore` tests could be deduplicated to only cover test cases that are specific to the behavior of the `sqlstore` implementation, and rely on the common interface tests where possible. This change would likely be of **medium complexity**.
- The `datastore` tests should be simplified and cleaned up. There is a heavy reliance on mutations of shared objects passed by reference from the suite to the store (as an example, see `TestBundleCRUD`, where returned objects are ignored and the same object is inspected repeatedly after mutation by the datastore). This change would likely be of **high complexity**.
- Well-known errors could be defined in the plugin SDK, improving testability and providing a tighter contract between the datastore core and plugins. Currently errors are checked via string matching, grpc status checks and other approaches, which doesn't provide a tight contract for plugins and makes tests challenging to write.

### Open questions and areas for improvement
- Closing a datastore with the plugintest closer seems to error
