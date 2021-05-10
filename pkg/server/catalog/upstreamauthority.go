package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/awspca"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/awssecret"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/disk"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/gcpcas"
	spireplugin "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/spire"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/vault"
)

type upstreamAuthorityRepository struct {
	upstreamauthority.Repository
}

func (repo *upstreamAuthorityRepository) Binder() interface{} {
	return repo.SetUpstreamAuthority
}

func (repo *upstreamAuthorityRepository) Constraints() catalog.Constraints {
	return catalog.MaybeOne()
}

func (repo *upstreamAuthorityRepository) Versions() []catalog.Version {
	return []catalog.Version{upstreamAuthorityV0{}}
}

func (repo *upstreamAuthorityRepository) LegacyVersion() (catalog.Version, bool) {
	return upstreamAuthorityV0{}, true
}

func (repo *upstreamAuthorityRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		awssecret.BuiltIn(),
		awspca.BuiltIn(),
		gcpcas.BuiltIn(),
		vault.BuiltIn(),
		spireplugin.BuiltIn(),
		disk.BuiltIn(),
	}
}

type upstreamAuthorityV0 struct{}

func (upstreamAuthorityV0) New() catalog.Facade { return new(upstreamauthority.V0) }
func (upstreamAuthorityV0) Deprecated() bool    { return false }
