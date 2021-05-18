package upstreamauthority

type Repository struct {
	UpstreamAuthority UpstreamAuthority
}

func (repo *Repository) GetUpstreamAuthority() (UpstreamAuthority, bool) {
	return repo.UpstreamAuthority, repo.UpstreamAuthority != nil
}

func (repo *Repository) SetUpstreamAuthority(upstreamAuthority UpstreamAuthority) {
	repo.UpstreamAuthority = upstreamAuthority
}

func (repo *Repository) ClearUpstreamAuthority() {
	repo.UpstreamAuthority = nil
}

func (repo *Repository) Clear() {
	repo.UpstreamAuthority = nil
}
