package nodeattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
)

type NodeAttestor interface {
	catalog.PluginInfo

	Attest(ctx context.Context, payload []byte, challengeFn func(ctx context.Context, challenge []byte) ([]byte, error)) (*AttestResult, error)
}

type AttestResult struct {
	AgentID     string
	Selectors   []*common.Selector
	CanReattest bool
}
