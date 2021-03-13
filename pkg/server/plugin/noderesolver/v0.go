package noderesolver

import (
	"context"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
	noderesolverv0 "github.com/spiffe/spire/proto/spire/server/noderesolver/v0"
)

type V0 struct {
	plugin.Facade

	Plugin noderesolverv0.NodeResolver
}

func (v0 V0) Resolve(ctx context.Context, agentID string) ([]*common.Selector, error) {
	resp, err := v0.Plugin.Resolve(ctx, &noderesolverv0.ResolveRequest{
		BaseSpiffeIdList: []string{agentID},
	})
	if err != nil {
		return nil, v0.WrapErr(err)
	}
	selectors := resp.Map[agentID]
	if selectors == nil {
		return nil, nil
	}
	return selectors.Entries, nil
}
