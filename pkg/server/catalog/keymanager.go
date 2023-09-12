package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"

	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/awskms"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/azurekeyvault"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/disk"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/gcpkms"
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
	return []catalog.Version{keyManagerV1{}}
}

func (repo *keyManagerRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		awskms.BuiltIn(),
		disk.BuiltIn(),
		gcpkms.BuiltIn(),
		azurekeyvault.BuiltIn(),
		memory.BuiltIn(),
	}
}

type keyManagerV1 struct{}

func (keyManagerV1) New() catalog.Facade { return new(keymanager.V1) }
func (keyManagerV1) Deprecated() bool    { return false }
