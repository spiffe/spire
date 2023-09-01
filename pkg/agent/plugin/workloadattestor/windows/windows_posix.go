//go:build !windows
// +build !windows

package windows

import (
	"context"

	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
	configv1.UnsafeConfigServer
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Configure(context.Context, *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	return nil, status.Error(codes.Unimplemented, "plugin not supported in this platform")
}
