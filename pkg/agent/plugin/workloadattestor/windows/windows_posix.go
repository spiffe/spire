//go:build !windows
// +build !windows

package windows

import (
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName, workloadattestorv1.WorkloadAttestorPluginServer(p))
}
func New() *Plugin {
	return &Plugin{}
}
