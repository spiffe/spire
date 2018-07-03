package mock_nodeattestor

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/server/nodeattestor NodeAttestor,Plugin,Attest_Stream > nodeattestor.go"
