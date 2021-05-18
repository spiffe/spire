package noderesolver

type Repository struct {
	NodeResolvers map[string]NodeResolver
}

func (repo *Repository) GetNodeResolverNamed(name string) (NodeResolver, bool) {
	nodeResolver, ok := repo.NodeResolvers[name]
	return nodeResolver, ok
}

func (repo *Repository) SetNodeResolver(nodeResolver NodeResolver) {
	if repo.NodeResolvers == nil {
		repo.NodeResolvers = make(map[string]NodeResolver)
	}
	repo.NodeResolvers[nodeResolver.Name()] = nodeResolver
}

func (repo *Repository) Clear() {
	repo.NodeResolvers = nil
}
