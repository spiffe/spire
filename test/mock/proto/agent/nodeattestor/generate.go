package mock_nodeattestor

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/agent/nodeattestor NodeAttestor,NodeAttestorPlugin,NodeAttestor_FetchAttestationData_Stream > nodeattestor_mock.go"
