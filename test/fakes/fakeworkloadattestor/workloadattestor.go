package fakeworkloadattestor

import (
	"context"
	"fmt"
	"sync"

	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
)

type WorkloadAttestor struct {
	mu   sync.RWMutex
	pids map[int32][]*common.Selector
}

var _ workloadattestor.Plugin = (*WorkloadAttestor)(nil)

func New() *WorkloadAttestor {
	return &WorkloadAttestor{
		pids: make(map[int32][]*common.Selector),
	}
}

func (p *WorkloadAttestor) SetSelectors(pid int32, sels []*common.Selector) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pids[pid] = sels
}

func (p *WorkloadAttestor) Attest(ctx context.Context, req *workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	s, ok := p.pids[req.Pid]
	if !ok {
		return nil, fmt.Errorf("cannot attest pid %d", req.Pid)
	}

	return &workloadattestor.AttestResponse{
		Selectors: s,
	}, nil
}

func (p *WorkloadAttestor) Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (p *WorkloadAttestor) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
