package bundlepublisher

type Repository struct {
	BundlePublishers []BundlePublisher
}

func (repo *Repository) GetBundlePublishers() []BundlePublisher {
	return repo.BundlePublishers
}

func (repo *Repository) AddBundlePublisher(bundlePublisher BundlePublisher) {
	repo.BundlePublishers = append(repo.BundlePublishers, bundlePublisher)
}

func (repo *Repository) Clear() {
	repo.BundlePublishers = nil
}
