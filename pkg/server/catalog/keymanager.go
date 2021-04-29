package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"

	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/awskms"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/disk"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
)

type keyManagerRepository struct {
	keymanager.Repository
}

func (repo *keyManagerRepository) Binder() interface{} {
	return repo.SetKeyManager
}

func (repo *keyManagerRepository) Constraints() catalog.Constraints {
	return catalog.ExactlyOne()
}

func (repo *keyManagerRepository) Versions() []catalog.Version {
	return []catalog.Version{keyManagerV0{}}
}

func (repo *keyManagerRepository) LegacyVersion() (catalog.Version, bool) {
	return keyManagerV0{}, true
}

func (repo *keyManagerRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		awskms.BuiltIn(),
		disk.BuiltIn(),
		memory.BuiltIn(),
	}
}

type keyManagerV0 struct{}

func (keyManagerV0) New() catalog.Facade { return new(keymanager.V0) }
func (keyManagerV0) Deprecated() bool    { return false }
