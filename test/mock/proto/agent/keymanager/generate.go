package mock_keymanager

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/agent/keymanager KeyManager,Plugin > keymanager_mock.go"
