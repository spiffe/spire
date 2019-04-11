package mock_manager

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/pkg/agent/manager Manager > manager_mock.go"
