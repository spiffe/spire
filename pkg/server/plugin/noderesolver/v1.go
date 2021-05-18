package noderesolver

import (
	"context"

	noderesolverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/noderesolver/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
)

type V1 struct {
	plugin.Facade
	noderesolverv1.NodeResolverPluginClient
}

func (v1 *V1) Resolve(ctx context.Context, agentID string) ([]*common.Selector, error) {
	resp, err := v1.NodeResolverPluginClient.Resolve(ctx, &noderesolverv1.ResolveRequest{
		AgentId: agentID,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}
	var selectors []*common.Selector
	if resp.SelectorValues != nil {
		selectors = make([]*common.Selector, 0, len(resp.SelectorValues))
		for _, selectorValue := range resp.SelectorValues {
			selectors = append(selectors, &common.Selector{
				Type:  v1.Name(),
				Value: selectorValue,
			})
		}
	}
	return selectors, nil
}
