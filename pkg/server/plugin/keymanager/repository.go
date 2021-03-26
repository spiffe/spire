package keymanager

type Repository struct {
	KeyManager KeyManager
}

func (repo *Repository) GetKeyManager() KeyManager {
	return repo.KeyManager
}

func (repo *Repository) SetKeyManager(keyManager KeyManager) {
	repo.KeyManager = keyManager
}

func (repo *Repository) Clear() {
	repo.KeyManager = nil
}
