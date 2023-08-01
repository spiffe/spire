package fakeworkloadattestor

import (
	"context"
	"fmt"
	"testing"

	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
)

func New(t *testing.T, name string, pids map[int32][]string) workloadattestor.WorkloadAttestor {
	server := workloadattestorv1.WorkloadAttestorPluginServer(&workloadAttestor{
		pids: pids,
	})
	wa := new(workloadattestor.V1)
	plugintest.Load(t, catalog.MakeBuiltIn(name, server), wa)
	return wa
}

type workloadAttestor struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer

	pids map[int32][]string
}

func (p *workloadAttestor) Attest(_ context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	s, ok := p.pids[req.Pid]
	if !ok {
		return nil, fmt.Errorf("cannot attest pid %d", req.Pid)
	}

	return &workloadattestorv1.AttestResponse{
		SelectorValues: s,
	}, nil
}
