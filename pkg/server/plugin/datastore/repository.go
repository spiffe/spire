package datastore

type Repository struct {
	DataStore DataStore
}

func (repo *Repository) GetDataStore() DataStore {
	return repo.DataStore
}

func (repo *Repository) SetDataStore(dataStore DataStore) {
	repo.DataStore = dataStore
}

func (repo *Repository) Clear() {
	repo.DataStore = nil
}

func (repo *Repository) ClearDataStore() {
	repo.DataStore = nil
}
