package mock_node

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/api/node NodeClient,Node_AttestClient,Node_AttestServer,Node_FetchX509SVIDClient,NodeServer,Node_FetchX509SVIDServer > node.go"
