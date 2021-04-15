package fakeworkloadattestor

import (
	"context"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	workloadattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/workloadattestor/v0"
	"github.com/spiffe/spire/test/spiretest"
)

func New(t *testing.T, name string, pids map[int32][]*common.Selector) workloadattestor.WorkloadAttestor {
	plugin := &workloadAttestor{
		pids: pids,
	}
	var wa workloadattestor.V0
	spiretest.LoadPlugin(t, catalog.MakePlugin(name, workloadattestorv0.PluginServer(plugin)), &wa)
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
