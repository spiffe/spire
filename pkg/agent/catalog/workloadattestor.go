package catalog

import (
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/k8s"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/unix"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/windows"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type workloadAttestorRepository struct {
	workloadattestor.Repository
}

func (repo *workloadAttestorRepository) Binder() interface{} {
	return repo.AddWorkloadAttestor
}

func (repo *workloadAttestorRepository) Constraints() catalog.Constraints {
	return catalog.AtLeastOne()
}

func (repo *workloadAttestorRepository) Versions() []catalog.Version {
	return []catalog.Version{workloadAttestorV1{}}
}

func (repo *workloadAttestorRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		docker.BuiltIn(),
		k8s.BuiltIn(),
		unix.BuiltIn(),
		windows.BuiltIn(),
	}
}

type workloadAttestorV1 struct{}

func (workloadAttestorV1) New() catalog.Facade { return new(workloadattestor.V1) }
func (workloadAttestorV1) Deprecated() bool    { return false }
