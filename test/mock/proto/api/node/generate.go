package mock_node

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/api/node NodeClient,Node_FetchSVIDClient,NodeServer,Node_FetchSVIDServer > node.go"
