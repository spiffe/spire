package tailscale

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_tailscale "github.com/spiffe/spire/pkg/common/plugin/tailscale"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

var (
	trustDomain = "example.org"
	// Reuse x509pop fixtures — the agent plugin just loads PEM certs
	// and sends them; it doesn't care about the cert contents.
	leafKeyPath  = fixture.Join("nodeattestor", "x509pop", "leaf-key.pem")
	leafCertPath = fixture.Join("nodeattestor", "x509pop", "leaf-crt-bundle.pem")

	streamBuilder = nodeattestortest.ServerStream(common_tailscale.PluginName)
)

func TestTailscale(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	leafCert *x509.Certificate
	bundle   [][]byte
}

func (s *Suite) SetupSuite() {
	kp, err := tls.LoadX509KeyPair(leafCertPath, leafKeyPath)
	s.Require().NoError(err)

	s.leafCert, err = x509.ParseCertificate(kp.Certificate[0])
	s.Require().NoError(err)

	s.bundle = kp.Certificate
}

func (s *Suite) TestAttestSuccess() {
	p := s.loadAndConfigurePlugin()

	expectPayload := s.marshal(common_tailscale.AttestationData{
		Certificates: s.bundle,
	})

	challenge, err := x509pop.GenerateChallenge(s.leafCert)
	s.Require().NoError(err)
	challengeBytes := s.marshal(challenge)

	err = p.Attest(context.Background(), streamBuilder.
		ExpectThenChallenge(expectPayload, challengeBytes).
		Handle(func(challengeResponse []byte) ([]byte, error) {
			response := new(x509pop.Response)
			if err := json.Unmarshal(challengeResponse, response); err != nil {
				return nil, err
			}
			return nil, x509pop.VerifyChallengeResponse(s.leafCert.PublicKey, challenge, response)
		}).Build())
	s.Require().NoError(err)
}

func (s *Suite) TestAttestFailure() {
	// not configured
	err := s.loadPlugin().Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "nodeattestor(tailscale): not configured")

	p := s.loadAndConfigurePlugin()

	// malformed challenge
	err = p.Attest(context.Background(), streamBuilder.IgnoreThenChallenge([]byte("")).Build())
	s.RequireGRPCStatusContains(err, codes.Internal, "nodeattestor(tailscale): unable to unmarshal challenge")

	// empty challenge
	err = p.Attest(context.Background(), streamBuilder.IgnoreThenChallenge(s.marshal(x509pop.Challenge{})).Build())
	s.RequireGRPCStatusContains(err, codes.Internal, "nodeattestor(tailscale): failed to calculate challenge response")
}

func (s *Suite) TestConfigure() {
	var err error

	// malformed
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.Configure(`bad juju`))
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "server core configuration must contain trust_domain")

	// missing cert_path
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`
			key_path = "blah"
		`),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "cert_path is required")

	// missing key_path
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`
			cert_path = "blah"
		`),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "key_path is required")

	// cannot load keypair
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`
			cert_path = "blah"
			key_path = "blah"
		`),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to load keypair")
}

func (s *Suite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), na, options...)
	return na
}

func (s *Suite) loadAndConfigurePlugin() nodeattestor.NodeAttestor {
	config := fmt.Sprintf(`
		cert_path = %q
		key_path = %q`, leafCertPath, leafKeyPath)
	return s.loadPlugin(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString(trustDomain),
		}),
		plugintest.Configure(config),
	)
}

func (s *Suite) marshal(obj any) []byte {
	data, err := json.Marshal(obj)
	s.Require().NoError(err)
	return data
}
