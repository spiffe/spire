package mock_datastore

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/server/datastore DataStore,DataStorePlugin > datastore.go"
