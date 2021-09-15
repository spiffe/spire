package svidstore

type Repository struct {
	SVIDStores map[string]SVIDStore
}

func (repo *Repository) GetSVIDStoreNamed(name string) (SVIDStore, bool) {
	svidStore, ok := repo.SVIDStores[name]
	return svidStore, ok
}

func (repo *Repository) SetSVIDStore(svidStore SVIDStore) {
	if repo.SVIDStores == nil {
		repo.SVIDStores = make(map[string]SVIDStore)
	}
	repo.SVIDStores[svidStore.Name()] = svidStore
}

func (repo *Repository) Clear() {
	repo.SVIDStores = nil
}
