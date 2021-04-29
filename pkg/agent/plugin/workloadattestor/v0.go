package workloadattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
	workloadattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/workloadattestor/v0"
)

type V0 struct {
	plugin.Facade
	workloadattestorv0.WorkloadAttestorPluginClient
}

func (v0 *V0) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	resp, err := v0.WorkloadAttestorPluginClient.Attest(ctx, &workloadattestorv0.AttestRequest{
		Pid: int32(pid),
	})
	if err != nil {
		return nil, v0.WrapErr(err)
	}
	return resp.Selectors, nil
}
