package tailscale

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	common "github.com/spiffe/spire/pkg/common/plugin/tailscale"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
)

var streamBuilder = nodeattestortest.ServerStream(common.PluginName)

func TestTailscale(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite
}

func (s *Suite) TestAttestSuccess() {
	na := s.loadPlugin()
	err := na.Attest(s.T().Context(), streamBuilder.ExpectAndBuild([]byte("{}")))
	s.Require().NoError(err)
}

func (s *Suite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), na, options...)
	return na
}
