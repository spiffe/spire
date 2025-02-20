package workloadattestor

import (
	"context"
	"fmt"

	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
)

type V1 struct {
	plugin.Facade
	workloadattestorv1.WorkloadAttestorPluginClient
}

func (v1 *V1) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	pidInt32, err := util.CheckedCast[int32](pid)
	if err != nil {
		return nil, v1.WrapErr(fmt.Errorf("invalid value for PID: %w", err))
	}
	resp, err := v1.WorkloadAttestorPluginClient.Attest(ctx, &workloadattestorv1.AttestRequest{
		Pid: pidInt32,
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
