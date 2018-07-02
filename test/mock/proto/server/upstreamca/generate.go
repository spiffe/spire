package mock_upstreamca

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/server/upstreamca UpstreamCA,UpstreamCAPlugin > upstreamca.go"
