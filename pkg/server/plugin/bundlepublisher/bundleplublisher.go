package bundlepublisher

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
)

type BundlePublisher interface {
	catalog.PluginInfo

	PublishBundle(ctx context.Context, bundle *common.Bundle) error
}
