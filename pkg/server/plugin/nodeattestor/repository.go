package nodeattestor

type Repository struct {
	NodeAttestors map[string]NodeAttestor
}

func (repo *Repository) GetNodeAttestorNamed(name string) (NodeAttestor, bool) {
	nodeAttestor, ok := repo.NodeAttestors[name]
	return nodeAttestor, ok
}

func (repo *Repository) SetNodeAttestor(nodeAttestor NodeAttestor) {
	if repo.NodeAttestors == nil {
		repo.NodeAttestors = make(map[string]NodeAttestor)
	}
	repo.NodeAttestors[nodeAttestor.Name()] = nodeAttestor
}

func (repo *Repository) Clear() {
	repo.NodeAttestors = nil
}
