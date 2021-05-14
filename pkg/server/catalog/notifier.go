package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/pkg/server/plugin/notifier/gcsbundle"
	"github.com/spiffe/spire/pkg/server/plugin/notifier/k8sbundle"
)

type notifierRepository struct {
	notifier.Repository
}

func (repo *notifierRepository) Binder() interface{} {
	return repo.AddNotifier
}

func (repo *notifierRepository) Constraints() catalog.Constraints {
	return catalog.ZeroOrMore()
}

func (repo *notifierRepository) Versions() []catalog.Version {
	return []catalog.Version{
		notifierV1{},
		// TODO: remove v0 once all of the built-ins have been migrated to v1
		notifierV0{},
	}
}

func (repo *notifierRepository) LegacyVersion() (catalog.Version, bool) {
	return notifierV0{}, true
}

func (repo *notifierRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		gcsbundle.BuiltIn(),
		k8sbundle.BuiltIn(),
	}
}

type notifierV1 struct{}

func (notifierV1) New() catalog.Facade { return new(notifier.V1) }
func (notifierV1) Deprecated() bool    { return false }

type notifierV0 struct{}

func (notifierV0) New() catalog.Facade { return new(notifier.V0) }
func (notifierV0) Deprecated() bool    { return true }
