package mock_node

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/spire/api/node NodeClient,Node_AttestClient,Node_AttestServer,Node_FetchX509SVIDClient,NodeServer,Node_FetchX509SVIDServer > node.go"
