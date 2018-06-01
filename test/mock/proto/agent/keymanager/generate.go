package mock_keymanager

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/agent/keymanager KeyManager > keymanager_mock.go"
