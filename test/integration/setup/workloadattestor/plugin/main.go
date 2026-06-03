//go:build !windows

package main

import (
	"context"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
)

type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
}

func (p *Plugin) Attest(_ context.Context, _ *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	return &workloadattestorv1.AttestResponse{
		SelectorValues: []string{"attested"},
	}, nil
}

func main() {
	plugin := new(Plugin)
	pluginmain.Serve(
		workloadattestorv1.WorkloadAttestorPluginServer(plugin),
	)
}
