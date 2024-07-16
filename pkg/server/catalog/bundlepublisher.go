package catalog

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher/awsrolesanywhere"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher/awss3"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher/gcpcloudstorage"
)

type bundlePublisherRepository struct {
	bundlepublisher.Repository
}

func (repo *bundlePublisherRepository) Binder() any {
	return repo.AddBundlePublisher
}

func (repo *bundlePublisherRepository) Constraints() catalog.Constraints {
	return catalog.ZeroOrMore()
}

func (repo *bundlePublisherRepository) Versions() []catalog.Version {
	return []catalog.Version{bundlePublisherV1{}}
}

func (repo *bundlePublisherRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		awss3.BuiltIn(),
		gcpcloudstorage.BuiltIn(),
		awsrolesanywhere.BuiltIn(),
	}
}

type bundlePublisherV1 struct{}

func (bundlePublisherV1) New() catalog.Facade { return new(bundlepublisher.V1) }
func (bundlePublisherV1) Deprecated() bool    { return false }
