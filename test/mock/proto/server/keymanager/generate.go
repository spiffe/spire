package mock_keymanager

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/server/keymanager KeyManager,Plugin > keymanager.go"
