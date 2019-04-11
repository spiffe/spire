package mock_datastore

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/server/datastore DataStore,DataStoreServer > datastore.go"
