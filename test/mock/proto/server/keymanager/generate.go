package mock_keymanager

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/server/keymanager KeyManager,KeyManagerServer > keymanager.go"
