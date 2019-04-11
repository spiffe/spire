package mock_keymanager

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/agent/keymanager KeyManager,KeyManagerServer > keymanager_mock.go"
