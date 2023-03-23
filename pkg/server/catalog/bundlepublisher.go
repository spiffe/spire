package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
)

type bundlePublisherRepository struct {
	bundlepublisher.Repository
}

func (repo *bundlePublisherRepository) Binder() interface{} {
	return repo.AddBundlePublisher
}

func (repo *bundlePublisherRepository) Constraints() catalog.Constraints {
	return catalog.ZeroOrMore()
}

func (repo *bundlePublisherRepository) Versions() []catalog.Version {
	return []catalog.Version{bundlePublisherV1{}}
}

func (repo *bundlePublisherRepository) BuiltIns() []catalog.BuiltIn {
	return nil
}

type bundlePublisherV1 struct{}

func (bundlePublisherV1) New() catalog.Facade { return new(bundlepublisher.V1) }
func (bundlePublisherV1) Deprecated() bool    { return false }
