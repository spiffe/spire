package mock_catalog

//go:generate sh -c "mockgen github.com/spiffe/spire/pkg/common/catalog Catalog > mock_catalog.go"
//go:generate sh -c "mockgen github.com/spiffe/spire/pkg/common/catalog Plugin > mock_plugin.go"
