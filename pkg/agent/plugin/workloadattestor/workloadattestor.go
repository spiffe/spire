package workloadattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
)

type WorkloadAttestor interface {
	catalog.PluginInfo

	Attest(ctx context.Context, pid int) ([]*common.Selector, error)
}
