package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver/azure"
)

type nodeResolverRepository struct {
	noderesolver.Repository
}

func (repo *nodeResolverRepository) Binder() interface{} {
	return repo.SetNodeResolver
}

func (repo *nodeResolverRepository) Constraints() catalog.Constraints {
	return catalog.ZeroOrMore()
}

func (repo *nodeResolverRepository) Versions() []catalog.Version {
	return []catalog.Version{nodeResolverV0{}}
}

func (repo *nodeResolverRepository) LegacyVersion() (catalog.Version, bool) {
	return nodeResolverV0{}, true
}

func (repo *nodeResolverRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		azure.BuiltIn(),
	}
}

type nodeResolverV0 struct{}

func (nodeResolverV0) New() catalog.Facade { return new(noderesolver.V0) }
func (nodeResolverV0) Deprecated() bool    { return false }
