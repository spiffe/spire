package credentialcomposer

type Repository struct {
	CredentialComposers []CredentialComposer
}

func (repo *Repository) GetCredentialComposers() []CredentialComposer {
	return repo.CredentialComposers
}

func (repo *Repository) AddCredentialComposer(credentialComposer CredentialComposer) {
	repo.CredentialComposers = append(repo.CredentialComposers, credentialComposer)
}

func (repo *Repository) Clear() {
	repo.CredentialComposers = nil
}
