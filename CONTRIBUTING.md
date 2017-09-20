In addition to the guidelines covered in the SPIFFE project
[CONTRIBUTING](https://github.com/spiffe/spiffe/blob/master/CONTRIBUTING.md), the following
conventions apply to the SPIRE repository:

### Directory layout

**/cmd/{spire-server,spire-agent}/**

The CLI implementations of the agent and server commands

**/pkg/{agent,server}/**

The main logic of the agent and server processes and their support packages

**/pkg/common/**

Common functionality for agent, server, and plugins

**/plugin/{agent,server}/\<name\>/**

The implementation of each plugin and their support packages

**/proto/{agent,server,api}/\<name\>/**

gRPC .proto files, their generated .pb.go, and README_pb.md.

The protobuf package names should be `spire.{server,agent,api,common}.<name>` and the go package name
should be specified with `option go_package = "<name>";``

### Interfaces

Packages should be exported through interfaces. Interaction with packages must be done through these
interfaces

Interfaces should be defined in their own file, named (in lowercase) after the name of the
interface. eg. `foodata.go` implements `type FooData interface{}`

### Mocks

Unit tests should avoid mock tests as much as possible. When necessary we should inject mocked
object generated through mockgen
