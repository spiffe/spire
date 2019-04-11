package mock_cache

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/pkg/agent/manager/cache Cache > cache_mock.go"
//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/pkg/agent/manager/cache Subscriber > subscriber_mock.go"
