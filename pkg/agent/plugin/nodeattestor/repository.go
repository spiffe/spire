package nodeattestor

type Repository struct {
	NodeAttestor NodeAttestor
}

func (repo *Repository) GetNodeAttestor() NodeAttestor {
	return repo.NodeAttestor
}

func (repo *Repository) SetNodeAttestor(nodeAttestor NodeAttestor) {
	repo.NodeAttestor = nodeAttestor
}

func (repo *Repository) Clear() {
	repo.NodeAttestor = nil
}
