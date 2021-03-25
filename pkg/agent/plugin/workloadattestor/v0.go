package workloadattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/plugin"
	workloadattestorv0 "github.com/spiffe/spire/proto/spire/agent/workloadattestor/v0"
	"github.com/spiffe/spire/proto/spire/common"
)

type V0 struct {
	plugin.Facade

	Plugin workloadattestorv0.WorkloadAttestor
}

func (v0 V0) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	resp, err := v0.Plugin.Attest(ctx, &workloadattestorv0.AttestRequest{
		Pid: int32(pid),
	})
	if err != nil {
		return nil, v0.WrapErr(err)
	}
	return resp.Selectors, nil
}
