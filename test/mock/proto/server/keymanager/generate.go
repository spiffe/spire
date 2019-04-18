package mock_keymanager

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/spire/server/keymanager KeyManager,KeyManagerServer > keymanager.go"
