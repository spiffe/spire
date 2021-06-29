package catalog

import (
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/aws"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/azure"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/gcp"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/jointoken"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8s/psat"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8s/sat"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/sshpop"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/x509pop"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type nodeAttestorRepository struct {
	nodeattestor.Repository
}

func (repo *nodeAttestorRepository) Binder() interface{} {
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

func (repo *nodeAttestorRepository) LegacyVersion() (catalog.Version, bool) {
	return nodeAttestorV0{}, true
}

func (repo *nodeAttestorRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		aws.BuiltIn(),
		azure.BuiltIn(),
		gcp.BuiltIn(),
		jointoken.BuiltIn(),
		psat.BuiltIn(),
		sat.BuiltIn(),
		sshpop.BuiltIn(),
		x509pop.BuiltIn(),
	}
}

type nodeAttestorV1 struct{}

func (nodeAttestorV1) New() catalog.Facade { return new(nodeattestor.V1) }
func (nodeAttestorV1) Deprecated() bool    { return false }

type nodeAttestorV0 struct{}

func (nodeAttestorV0) New() catalog.Facade { return new(nodeattestor.V0) }
func (nodeAttestorV0) Deprecated() bool    { return true }
