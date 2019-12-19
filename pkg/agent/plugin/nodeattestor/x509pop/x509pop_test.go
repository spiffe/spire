package x509pop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

func TestX509PoP(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	p          nodeattestor.Plugin
	leafBundle [][]byte
	leafCert   *x509.Certificate
}

func (s *Suite) SetupTest() {
	leafKeyPath := fixture.Join("nodeattestor", "x509pop", "leaf-key.pem")
	leafCertPath := fixture.Join("nodeattestor", "x509pop", "leaf-crt-bundle.pem")
	s.p = s.newPlugin()
	s.configure(leafKeyPath, leafCertPath, "")
}

func (s *Suite) newPlugin() nodeattestor.Plugin {
	var p nodeattestor.Plugin
	s.LoadPlugin(BuiltIn(), &p)
	return p
}

func (s *Suite) configure(privateKeyPath, certificatePath, intermediatesPath string) {
	require := s.Require()
	config := fmt.Sprintf(`
		private_key_path = %q 
		certificate_path = %q`, privateKeyPath, certificatePath)

	if intermediatesPath != "" {
		config += fmt.Sprintf(`
			intermediates_path = %q`, intermediatesPath)
	}

	resp, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: config,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	require.NoError(err)
	require.Equal(resp, &plugin.ConfigureResponse{})

	kp, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	require.NoError(err)

	certificates := kp.Certificate
	if intermediatesPath != "" {
		certs, err := util.LoadCertificates(intermediatesPath)
		require.NoError(err)
		for _, c := range certs {
			certificates = append(certificates, c.Raw)
		}
	}

	s.leafBundle = certificates
	s.leafCert, err = x509.ParseCertificate(s.leafBundle[0])
	require.NoError(err)
}

func (s *Suite) TestFetchAttestationDataSuccess() {
	require := s.Require()

	stream, done := s.fetchAttestationData()
	defer done()

	// first response has the attestation data
	resp, err := stream.Recv()
	require.NoError(err)
	require.NotNil(resp)
	require.Equal("x509pop", resp.AttestationData.Type)
	require.JSONEq(string(s.marshal(x509pop.AttestationData{
		Certificates: s.leafBundle,
	})), string(resp.AttestationData.Data))
	require.Nil(resp.Response)

	// send a challenge
	challenge, err := x509pop.GenerateChallenge(s.leafCert)
	require.NoError(err)
	challengeBytes, err := json.Marshal(challenge)
	require.NoError(err)
	err = stream.Send(&nodeattestor.FetchAttestationDataRequest{
		Challenge: challengeBytes,
	})
	require.NoError(err)

	// recv the response
	resp, err = stream.Recv()
	require.NoError(err)
	require.Nil(resp.AttestationData)
	require.NotEmpty(resp.Response)

	// verify signature
	response := new(x509pop.Response)
	s.unmarshal(resp.Response, response)
	err = x509pop.VerifyChallengeResponse(s.leafCert.PublicKey, challenge, response)
	require.NoError(err)
}

func (s *Suite) TestFetchAttestationDataSuccessWithIntermediates() {
	leafKeyPath := fixture.Join("nodeattestor", "x509pop", "leaf-key.pem")
	leafCertPath := fixture.Join("nodeattestor", "x509pop", "leaf.pem")
	intermediatePath := fixture.Join("nodeattestor", "x509pop", "intermediate.pem")
	s.configure(leafKeyPath, leafCertPath, intermediatePath)
	s.TestFetchAttestationDataSuccess()
}

func (s *Suite) TestFetchAttestationDataFailure() {
	require := s.Require()

	challengeFails := func(challenge []byte, expected string) {
		stream, done := s.fetchAttestationData()
		defer done()

		resp, err := stream.Recv()
		require.NoError(err)
		require.NotNil(resp)

		require.NoError(stream.Send(&nodeattestor.FetchAttestationDataRequest{
			Challenge: challenge,
		}))

		resp, err = stream.Recv()
		s.RequireErrorContains(err, expected)
		require.Nil(resp)
	}

	// not configured
	stream, err := s.newPlugin().FetchAttestationData(context.Background())
	require.NoError(err)
	defer func() {
		require.NoError(stream.CloseSend())
	}()
	resp, err := stream.Recv()
	s.RequireGRPCStatus(err, codes.Unknown, "x509pop: not configured")
	require.Nil(resp)

	// malformed challenge
	challengeFails(nil, "x509pop: unable to unmarshal challenge")

	// empty challenge
	challengeFails(s.marshal(x509pop.Challenge{}), "x509pop: failed to calculate challenge response")
}

func (s *Suite) TestConfigure() {
	require := s.Require()

	// malformed
	resp, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `bad juju`,
	})
	s.RequireGRPCStatusContains(err, codes.Unknown, "x509pop: unable to decode configuration")
	require.Nil(resp)

	// missing global configuration
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		private_key_path = "blah"
		certificate_path = "blah"
		`,
	})
	s.RequireGRPCStatus(err, codes.Unknown, "x509pop: global configuration is required")
	require.Nil(resp)

	// missing trust_domain
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		private_key_path = "blah"
		certificate_path = "blah"
		`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{},
	})
	s.RequireGRPCStatus(err, codes.Unknown, "x509pop: trust_domain is required")
	require.Nil(resp)

	// missing private_key_path
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		certificate_path = "blah"
		`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "spiffe://example.org"},
	})
	s.RequireGRPCStatus(err, codes.Unknown, "x509pop: private_key_path is required")
	require.Nil(resp)

	// missing certificate_path
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		private_key_path = "blah"
		`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "spiffe://example.org"},
	})
	s.RequireGRPCStatus(err, codes.Unknown, "x509pop: certificate_path is required")
	require.Nil(resp)

	// cannot load keypair
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		private_key_path = "blah"
		certificate_path = "blah"
		`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "spiffe://example.org"},
	})
	s.RequireGRPCStatusContains(err, codes.Unknown, "x509pop: unable to load keypair")
	require.Nil(resp)

	// cannot load intermediates
	leafKeyPath := fixture.Join("nodeattestor", "x509pop", "leaf-key.pem")
	leafCertPath := fixture.Join("nodeattestor", "x509pop", "leaf-crt-bundle.pem")
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`
			private_key_path = %q 
			certificate_path = %q
			intermediates_path = "blah"`, leafKeyPath, leafCertPath),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "spiffe://example.org"},
	})
	s.RequireGRPCStatusContains(err, codes.Unknown, "x509pop: unable to load intermediate certificates")
	require.Nil(resp)
}

func (s *Suite) TestGetPluginInfo() {
	require := s.Require()

	resp, err := s.p.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	require.NoError(err)
	require.Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *Suite) fetchAttestationData() (nodeattestor.NodeAttestor_FetchAttestationDataClient, func()) {
	stream, err := s.p.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	return stream, func() {
		s.Require().NoError(stream.CloseSend())
	}
}

func (s *Suite) marshal(obj interface{}) []byte {
	data, err := json.Marshal(obj)
	s.Require().NoError(err)
	return data
}

func (s *Suite) unmarshal(data []byte, obj interface{}) {
	s.Require().NoError(json.Unmarshal(data, obj))
}
