//go:build windows

package unix

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

func TestConfigure(t *testing.T) {
	var err error
	loadPlugin(t, plugintest.CaptureConfigureError(&err), plugintest.Configure(""))
	spiretest.RequireGRPCStatusContains(t, err, codes.Unimplemented, "plugin not supported in this platform")
}

func loadPlugin(t *testing.T, options ...plugintest.Option) workloadattestor.WorkloadAttestor {
	p := new(workloadattestor.V1)
	plugintest.Load(t, BuiltIn(), p, options...)
	return p
}
