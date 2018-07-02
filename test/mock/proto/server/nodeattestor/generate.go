package mock_nodeattestor

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/server/nodeattestor NodeAttestor,NodeAttestorPlugin,NodeAttestor_Attest_Stream > nodeattestor.go"
