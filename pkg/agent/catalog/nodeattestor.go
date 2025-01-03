package catalog

import (
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/awsiid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/azuremsi"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/gcpiit"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/httpchallenge"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/jointoken"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8spsat"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/sshpop"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/x509pop"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type nodeAttestorRepository struct {
	nodeattestor.Repository
}

func (repo *nodeAttestorRepository) Binder() any {
	return repo.SetNodeAttestor
}

func (repo *nodeAttestorRepository) Constraints() catalog.Constraints {
	return catalog.ExactlyOne()
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
		httpchallenge.BuiltIn(),
		jointoken.BuiltIn(),
		k8spsat.BuiltIn(),
		sshpop.BuiltIn(),
		tpmdevid.BuiltIn(),
		x509pop.BuiltIn(),
	}
}

type nodeAttestorV1 struct{}

func (nodeAttestorV1) New() catalog.Facade { return new(nodeattestor.V1) }
func (nodeAttestorV1) Deprecated() bool    { return false }
