package mock_upstreamca

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/spire/server/upstreamca UpstreamCA,UpstreamCAServer > upstreamca.go"
