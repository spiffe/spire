package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/datastore/cassandra"
)

type dataStoreRepository struct {
	datastore.Repository
}

func (repo *dataStoreRepository) Binder() any {
	return repo.SetDataStore
}

func (repo *dataStoreRepository) Constraints() catalog.Constraints {
	return catalog.MaybeOne()
}

func (repo *dataStoreRepository) Versions() []catalog.Version {
	return []catalog.Version{
		datastoreV1Alpha1{},
	}
}

func (repo *dataStoreRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		cassandra.BuiltIn(),
	}
}

type datastoreV1Alpha1 struct{}

func (datastoreV1Alpha1) New() catalog.Facade { return new(datastore.V1Alpha1) }
func (datastoreV1Alpha1) Deprecated() bool    { return false }
