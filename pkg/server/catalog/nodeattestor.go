package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/azuremsi"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcpiit"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/jointoken"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8spsat"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8ssat"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/sshpop"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/tpmdevid"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/x509pop"
)

type nodeAttestorRepository struct {
	nodeattestor.Repository
}

func (repo *nodeAttestorRepository) Binder() any {
	return repo.SetNodeAttestor
}

func (repo *nodeAttestorRepository) Constraints() catalog.Constraints {
	return catalog.ZeroOrMore()
}

func (repo *nodeAttestorRepository) Versions() []catalog.Version {
	return []catalog.Version{
		nodeAttestorV1{},
	}
}

func (repo *nodeAttestorRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		awsiid.BuiltIn(),
		azuremsi.BuiltIn(),
		gcpiit.BuiltIn(),
		jointoken.BuiltIn(),
		k8spsat.BuiltIn(),
		k8ssat.BuiltIn(),
		sshpop.BuiltIn(),
		tpmdevid.BuiltIn(),
		x509pop.BuiltIn(),
	}
}

type nodeAttestorV1 struct{}

func (nodeAttestorV1) New() catalog.Facade { return new(nodeattestor.V1) }
func (nodeAttestorV1) Deprecated() bool    { return false }
