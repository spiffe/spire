package noderesolver

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
)

type NodeResolver interface {
	catalog.PluginInfo

	Resolve(ctx context.Context, agentID string) ([]*common.Selector, error)
}
