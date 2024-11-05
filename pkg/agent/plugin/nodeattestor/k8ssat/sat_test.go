package k8ssat

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

var (
	streamBuilder = nodeattestortest.ServerStream(pluginName)
)

func TestAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(AttestorSuite))
}

type AttestorSuite struct {
	spiretest.Suite

	dir string
}

func (s *AttestorSuite) SetupTest() {
	s.dir = s.TempDir()
}

func (s *AttestorSuite) TestAttestNotConfigured() {
	na := s.loadPlugin()
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "nodeattestor(k8s_sat): not configured")
}

func (s *AttestorSuite) TestAttestNoToken() {
	na := s.loadPluginWithTokenPath("example.org", s.joinPath("token"))
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "nodeattestor(k8s_sat): unable to load token from")
}

func (s *AttestorSuite) TestAttestEmptyToken() {
	na := s.loadPluginWithTokenPath("example.org", s.writeValue("token", ""))
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "nodeattestor(k8s_sat): unable to load token from")
}

func (s *AttestorSuite) TestAttestSuccess() {
	na := s.loadPluginWithTokenPath("example.org", s.writeValue("token", "TOKEN"))

	err := na.Attest(context.Background(), streamBuilder.ExpectAndBuild([]byte(`{"cluster":"production","token":"TOKEN"}`)))
	s.Require().NoError(err)
}

func (s *AttestorSuite) TestConfigure() {
	var err error

	// malformed configuration
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure("malformed"),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to decode configuration")

	// missing cluster
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(""),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "configuration missing cluster")

	// success
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`cluster = "production"`),
	)
	s.Require().NoError(err)
}

func (s *AttestorSuite) loadPluginWithTokenPath(trustDomain string, tokenPath string) nodeattestor.NodeAttestor {
	return s.loadPlugin(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString(trustDomain),
		}),
		plugintest.Configuref(`
			cluster = "production"
			token_path = %q`, tokenPath),
	)
}

func (s *AttestorSuite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), na, options...)
	return na
}

func (s *AttestorSuite) joinPath(path string) string {
	return filepath.Join(s.dir, path)
}

func (s *AttestorSuite) writeValue(path, data string) string {
	valuePath := s.joinPath(path)
	err := os.MkdirAll(filepath.Dir(valuePath), 0755)
	s.Require().NoError(err)
	err = os.WriteFile(valuePath, []byte(data), 0600)
	s.Require().NoError(err)
	return valuePath
}
