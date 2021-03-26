package fakeworkloadattestor

import (
	"context"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	workloadattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/workloadattestor/v0"
	"github.com/spiffe/spire/test/plugintest"
)

func New(t *testing.T, name string, pids map[int32][]*common.Selector) workloadattestor.WorkloadAttestor {
	server := workloadattestorv0.WorkloadAttestorPluginServer(&workloadAttestor{
		pids: pids,
	})
	wa := new(workloadattestor.V0)
	plugintest.Load(t, catalog.MakeBuiltIn(name, server), wa)
	return wa
}

type workloadAttestor struct {
	workloadattestorv0.UnimplementedWorkloadAttestorServer

	pids map[int32][]*common.Selector
}

func (p *workloadAttestor) Attest(ctx context.Context, req *workloadattestorv0.AttestRequest) (*workloadattestorv0.AttestResponse, error) {
	s, ok := p.pids[req.Pid]
	if !ok {
		return nil, fmt.Errorf("cannot attest pid %d", req.Pid)
	}

	return &workloadattestorv0.AttestResponse{
		Selectors: s,
	}, nil
}
