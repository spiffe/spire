package mock_noderesolver

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/server/noderesolver NodeResolver,NodeResolverClient,NodeResolverServer,NodeResolverPlugin > noderesolver.go"
