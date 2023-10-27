package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/disk"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
)

type keyManagerRepository struct {
	keymanager.Repository
}

func (repo *keyManagerRepository) Binder() any {
	return repo.SetKeyManager
}

func (repo *keyManagerRepository) Constraints() catalog.Constraints {
	return catalog.ExactlyOne()
}

func (repo *keyManagerRepository) Versions() []catalog.Version {
	return []catalog.Version{keyManagerV1{}}
}

func (repo *keyManagerRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		disk.BuiltIn(),
		memory.BuiltIn(),
	}
}

type keyManagerV1 struct{}

func (keyManagerV1) New() catalog.Facade { return new(keymanager.V1) }
func (keyManagerV1) Deprecated() bool    { return false }
