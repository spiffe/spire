package mock_noderesolver

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/spire/server/noderesolver NodeResolver,NodeResolverClient,NodeResolverServer > noderesolver.go"
