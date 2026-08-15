//go:build windows

package slurm

import (
	"context"

	"github.com/hashicorp/go-hclog"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
	)
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) SetLogger(hclog.Logger) {
}

func (p *Plugin) Attest(context.Context, *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	return nil, status.Error(codes.Unimplemented, "plugin not supported in this platform")
}

func (p *Plugin) AttestReference(context.Context, *workloadattestorv1.AttestReferenceRequest) (*workloadattestorv1.AttestReferenceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "plugin not supported in this platform")
}
