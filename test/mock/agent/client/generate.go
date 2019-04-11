package mock_client

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/pkg/agent/client Client > client_mock.go"
