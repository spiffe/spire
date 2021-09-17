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
	return []catalog.Version{nodeResolverV1{}}
}

func (repo *nodeResolverRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		azure.BuiltIn(),
	}
}

type nodeResolverV1 struct{}

func (nodeResolverV1) New() catalog.Facade { return new(noderesolver.V1) }
func (nodeResolverV1) Deprecated() bool    { return false }
