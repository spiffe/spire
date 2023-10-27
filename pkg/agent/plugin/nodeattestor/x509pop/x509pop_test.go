package x509pop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

var (
	leafKeyPath      = fixture.Join("nodeattestor", "x509pop", "leaf-key.pem")
	leafCertPath     = fixture.Join("nodeattestor", "x509pop", "leaf-crt-bundle.pem")
	intermediatePath = fixture.Join("nodeattestor", "x509pop", "intermediate.pem")

	streamBuilder = nodeattestortest.ServerStream(pluginName)
)

func TestX509PoP(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	leafCert                  *x509.Certificate
	bundleWithoutIntermediate [][]byte
	bundleWithIntermediate    [][]byte
}

func (s *Suite) SetupSuite() {
	kp, err := tls.LoadX509KeyPair(leafCertPath, leafKeyPath)
	s.Require().NoError(err)

	s.leafCert, err = x509.ParseCertificate(kp.Certificate[0])
	s.Require().NoError(err)

	s.bundleWithoutIntermediate = kp.Certificate

	intermediateCerts, err := util.LoadCertificates(intermediatePath)
	s.Require().NoError(err)
	s.bundleWithIntermediate = kp.Certificate
	for _, c := range intermediateCerts {
		s.bundleWithIntermediate = append(s.bundleWithIntermediate, c.Raw)
	}
}

func (s *Suite) TestAttestSuccess() {
	p := s.loadAndConfigurePlugin(false)
	s.testAttestSuccess(p, s.bundleWithoutIntermediate)
}

func (s *Suite) TestAttestSuccessWithIntermediates() {
	p := s.loadAndConfigurePlugin(true)
	s.testAttestSuccess(p, s.bundleWithIntermediate)
}

func (s *Suite) TestAttestFailure() {
	// not configured
	err := s.loadPlugin().Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "nodeattestor(x509pop): not configured")

	p := s.loadAndConfigurePlugin(false)

	// malformed challenge
	err = p.Attest(context.Background(), streamBuilder.IgnoreThenChallenge([]byte("")).Build())
	s.RequireGRPCStatusContains(err, codes.Internal, "nodeattestor(x509pop): unable to unmarshal challenge")

	// empty challenge
	err = p.Attest(context.Background(), streamBuilder.IgnoreThenChallenge(s.marshal(x509pop.Challenge{})).Build())
	s.RequireGRPCStatusContains(err, codes.Internal, "nodeattestor(x509pop): failed to calculate challenge response")
}

func (s *Suite) TestConfigure() {
	var err error

	// malformed
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.Configure(`bad juju`))
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to decode configuration")

	// missing private_key_path
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.Configure(`
			certificate_path = "blah"
		`),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "private_key_path is required")

	// missing certificate_path
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.Configure(`
			private_key_path = "blah"
		`),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "certificate_path is required")

	// cannot load keypair
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.Configure(`
			private_key_path = "blah"
			certificate_path = "blah"
		`),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to load keypair")

	// cannot load intermediates
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.Configuref(`
			private_key_path = %q
			certificate_path = %q
			intermediates_path = "blah"`, leafKeyPath, leafCertPath),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to load intermediate certificates")
}

func (s *Suite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), na, options...)
	return na
}

func (s *Suite) loadAndConfigurePlugin(withIntermediate bool) nodeattestor.NodeAttestor {
	config := fmt.Sprintf(`
		private_key_path = %q 
		certificate_path = %q`, leafKeyPath, leafCertPath)
	if withIntermediate {
		config += fmt.Sprintf(`
			intermediates_path = %q`, intermediatePath)
	}
	return s.loadPlugin(plugintest.Configure(config))
}

func (s *Suite) testAttestSuccess(p nodeattestor.NodeAttestor, expectBundle [][]byte) {
	expectPayload := s.marshal(x509pop.AttestationData{
		Certificates: expectBundle,
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

func (s *Suite) marshal(obj any) []byte {
	data, err := json.Marshal(obj)
	s.Require().NoError(err)
	return data
}
