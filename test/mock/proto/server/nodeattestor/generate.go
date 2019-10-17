package mock_nodeattestor

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/spire/server/nodeattestor NodeAttestor,NodeAttestorServer,NodeAttestor_AttestServer > nodeattestor.go"
