package k8spsat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/grpc/codes"
)

var (
	sampleKey     = testkey.MustRSA2048()
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
	s.T().Logf("failed: %s", err.Error())
	s.RequireGRPCStatusContains(err, codes.FailedPrecondition, "nodeattestor(k8s_psat): not configured")
}

func (s *AttestorSuite) TestAttestNoToken() {
	na := s.loadPluginWithTokenPath(s.joinPath("token"))
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "nodeattestor(k8s_psat): unable to load token from")
}

func (s *AttestorSuite) TestAttestEmptyToken() {
	na := s.loadPluginWithTokenPath(s.writeValue("token", ""))
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "nodeattestor(k8s_psat): unable to load token from")
}

func (s *AttestorSuite) TestAttestSuccess() {
	token, err := createPSAT("NAMESPACE", "POD-NAME")
	s.Require().NoError(err)

	na := s.loadPluginWithTokenPath(s.writeValue("token", token))

	err = na.Attest(context.Background(), streamBuilder.ExpectAndBuild(fmt.Appendf(nil, `{"cluster":"production","token":"%s"}`, token)))
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
	s.RequireGRPCStatus(err, codes.InvalidArgument, "missing required cluster block")

	// success
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`cluster = "production"`),
	)
	s.Require().NoError(err)
}

func (s *AttestorSuite) loadPluginWithTokenPath(tokenPath string) nodeattestor.NodeAttestor {
	return s.loadPlugin(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configuref(`
			cluster = "production"
			token_path = %q
		`, tokenPath),
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
	err := os.MkdirAll(filepath.Dir(valuePath), 0o755)
	s.Require().NoError(err)
	err = os.WriteFile(valuePath, []byte(data), 0o600)
	s.Require().NoError(err)
	return valuePath
}

// Creates a PSAT using the given namespace and podName (just for testing)
func createPSAT(namespace, podName string) (string, error) {
	// Create a jwt builder
	s, err := createSigner()
	if err != nil {
		return "", err
	}

	builder := jwt.Signed(s)

	// Set useful claims for testing
	claims := sat_common.PSATClaims{}
	claims.K8s.Namespace = namespace
	claims.K8s.Pod.Name = podName
	builder = builder.Claims(claims)

	// Serialize and return token
	token, err := builder.Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

func createSigner() (jose.Signer, error) {
	sampleSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       sampleKey,
	}, nil)
	if err != nil {
		return nil, err
	}

	return sampleSigner, nil
}
