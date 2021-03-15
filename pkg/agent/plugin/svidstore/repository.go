package svidstore

type Repository struct {
	SVIDStores []SVIDStore
}

func (repo *Repository) GetSVIDStores() []SVIDStore {
	return repo.SVIDStores
}

func (repo *Repository) AddSVIDStore(svidStore SVIDStore) {
	repo.SVIDStores = append(repo.SVIDStores, svidStore)
}

func (repo *Repository) SetSVIDStores(svidStores ...SVIDStore) {
	repo.SVIDStores = svidStores
}

func (repo *Repository) Clear() {
	repo.SVIDStores = nil
}
