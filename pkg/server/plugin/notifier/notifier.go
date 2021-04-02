package notifier

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
)

type Notifier interface {
	catalog.PluginInfo

	NotifyAndAdviseBundleLoaded(ctx context.Context, bundle *common.Bundle) error
	NotifyBundleUpdated(ctx context.Context, bundle *common.Bundle) error
}
