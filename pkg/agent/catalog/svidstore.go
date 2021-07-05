package catalog

import (
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type svidStoreRepository struct {
	svidstore.Repository
}

func (repo *svidStoreRepository) Binder() interface{} {
	return repo.AddSVIDStore
}

func (repo *svidStoreRepository) Constraints() catalog.Constraints {
	return catalog.MaybeOne()
}

func (repo *svidStoreRepository) Versions() []catalog.Version {
	return []catalog.Version{
		svidStoreV1{},
	}
}

func (repo *svidStoreRepository) LegacyVersion() (catalog.Version, bool) {
	return nil, false
}

func (repo *svidStoreRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{}
}

type svidStoreV1 struct{}

func (svidStoreV1) New() catalog.Facade { return new(svidstore.V1) }
func (svidStoreV1) Deprecated() bool    { return false }
