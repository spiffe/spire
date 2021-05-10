package notifier

type Repository struct {
	Notifiers []Notifier
}

func (repo *Repository) GetNotifiers() []Notifier {
	return repo.Notifiers
}

func (repo *Repository) AddNotifier(notifier Notifier) {
	repo.Notifiers = append(repo.Notifiers, notifier)
}

func (repo *Repository) Clear() {
	repo.Notifiers = nil
}
