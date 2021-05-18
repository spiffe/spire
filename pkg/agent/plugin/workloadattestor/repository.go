package workloadattestor

type Repository struct {
	WorkloadAttestors []WorkloadAttestor
}

func (repo *Repository) GetWorkloadAttestors() []WorkloadAttestor {
	return repo.WorkloadAttestors
}

func (repo *Repository) AddWorkloadAttestor(workloadattestor WorkloadAttestor) {
	repo.WorkloadAttestors = append(repo.WorkloadAttestors, workloadattestor)
}

func (repo *Repository) SetWorkloadAttestors(workloadAttestors ...WorkloadAttestor) {
	repo.WorkloadAttestors = workloadAttestors
}

func (repo *Repository) Clear() {
	repo.WorkloadAttestors = nil
}
