package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/awspca"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/awssecret"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/certmanager"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/disk"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/ejbca"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/gcpcas"
	spireplugin "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/spire"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/vault"
)

type upstreamAuthorityRepository struct {
	upstreamauthority.Repository
}

func (repo *upstreamAuthorityRepository) Binder() any {
	return repo.SetUpstreamAuthority
}

func (repo *upstreamAuthorityRepository) Constraints() catalog.Constraints {
	return catalog.MaybeOne()
}

func (repo *upstreamAuthorityRepository) Versions() []catalog.Version {
	return []catalog.Version{
		upstreamAuthorityV1{},
	}
}

func (repo *upstreamAuthorityRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		awssecret.BuiltIn(),
		awspca.BuiltIn(),
		gcpcas.BuiltIn(),
		vault.BuiltIn(),
		spireplugin.BuiltIn(),
		disk.BuiltIn(),
		certmanager.BuiltIn(),
		ejbca.BuiltIn(),
	}
}

type upstreamAuthorityV1 struct{}

func (upstreamAuthorityV1) New() catalog.Facade { return new(upstreamauthority.V1) }
func (upstreamAuthorityV1) Deprecated() bool    { return false }
