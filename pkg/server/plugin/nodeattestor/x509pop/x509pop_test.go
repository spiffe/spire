package x509pop

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
)

func TestX509PoP(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	p nodeattestor.Plugin

	rootCertPath     string
	leafBundle       [][]byte
	leafKey          crypto.PrivateKey
	leafCert         *x509.Certificate
	intermediateCert *x509.Certificate
	rootCert         *x509.Certificate
}

func (s *Suite) SetupTest() {
	require := s.Require()

	s.rootCertPath = fixture.Join("nodeattestor", "x509pop", "root-crt.pem")
	leafCertPath := fixture.Join("nodeattestor", "x509pop", "leaf-crt-bundle.pem")
	leafKeyPath := fixture.Join("nodeattestor", "x509pop", "leaf-key.pem")

	s.LoadPlugin(BuiltIn(), &s.p)

	kp, err := tls.LoadX509KeyPair(leafCertPath, leafKeyPath)
	require.NoError(err)
	s.leafBundle = kp.Certificate
	s.leafKey = kp.PrivateKey
	s.leafCert, err = x509.ParseCertificate(s.leafBundle[0])
	require.NoError(err)
	s.intermediateCert, err = x509.ParseCertificate(s.leafBundle[1])
	require.NoError(err)
	s.rootCert, err = util.LoadCert(s.rootCertPath)
	require.NoError(err)
}

func (s *Suite) TestAttestSuccess() {
	s.configure()

	require := s.Require()

	stream, done := s.attest()
	defer done()

	// send down good attestation data
	attestationData := &x509pop.AttestationData{
		Certificates: s.leafBundle,
	}
	err := stream.Send(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "x509pop",
			Data: s.marshal(attestationData),
		},
	})
	require.NoError(err)

	// receive and parse challenge
	resp, err := stream.Recv()
	require.NoError(err)
	require.Equal("", resp.BaseSPIFFEID)
	s.False(resp.Valid)
	s.NotEmpty(resp.Challenge)

	challenge := new(x509pop.Challenge)
	s.unmarshal(resp.Challenge, challenge)

	// calculate and send the response
	response, err := x509pop.CalculateResponse(s.leafKey, challenge)
	require.NoError(err)
	err = stream.Send(&nodeattestor.AttestRequest{
		Response: s.marshal(response),
	})
	require.NoError(err)

	// receive the attestation result
	resp, err = stream.Recv()
	require.NoError(err)
	s.True(resp.Valid)
	require.Equal("spiffe://example.org/spire/agent/x509pop/"+x509pop.Fingerprint(s.leafCert), resp.BaseSPIFFEID)
	require.Nil(resp.Challenge)
	require.Len(resp.Selectors, 3)
	require.EqualValues([]*common.Selector{
		{Type: "x509pop", Value: "subject:cn:some common name"},
		{Type: "x509pop", Value: "ca:fingerprint:" + x509pop.Fingerprint(s.intermediateCert)},
		{Type: "x509pop", Value: "ca:fingerprint:" + x509pop.Fingerprint(s.rootCert)},
	}, resp.Selectors)
}

func (s *Suite) TestAttestFailure() {
	require := s.Require()

	makeData := func(attestationData *x509pop.AttestationData) *common.AttestationData {
		return &common.AttestationData{
			Type: "x509pop",
			Data: s.marshal(attestationData),
		}
	}

	attestFails := func(attestationData *common.AttestationData, expected string) {
		stream, done := s.attest()
		defer done()

		require.NoError(stream.Send(&nodeattestor.AttestRequest{
			AttestationData: attestationData,
		}))

		resp, err := stream.Recv()
		s.errorContains(err, expected)
		require.Nil(resp)
	}

	challengeResponseFails := func(response string, expected string) {
		stream, done := s.attest()
		defer done()

		require.NoError(stream.Send(&nodeattestor.AttestRequest{
			AttestationData: makeData(&x509pop.AttestationData{
				Certificates: s.leafBundle,
			}),
		}))

		resp, err := stream.Recv()
		require.NoError(err)
		s.NotNil(resp)

		require.NoError(stream.Send(&nodeattestor.AttestRequest{
			Response: []byte(response),
		}))

		resp, err = stream.Recv()
		s.errorContains(err, expected)
		require.Nil(resp)
	}

	// not configured yet
	attestFails(&common.AttestationData{},
		"x509pop: not configured")

	// now configure
	s.configure()

	// unexpected data type
	attestFails(&common.AttestationData{Type: "foo"},
		"x509pop: unexpected attestation data type \"foo\"")

	// malformed data
	attestFails(&common.AttestationData{Type: "x509pop"},
		"x509pop: failed to unmarshal data")

	// no certificate
	attestFails(makeData(&x509pop.AttestationData{}),
		"x509pop: no certificate to attest")

	// malformed leaf
	attestFails(makeData(&x509pop.AttestationData{Certificates: [][]byte{{0x00}}}),
		"x509pop: unable to parse leaf certificate")

	// malformed intermediate
	attestFails(makeData(&x509pop.AttestationData{Certificates: [][]byte{s.leafBundle[0], {0x00}}}),
		"x509pop: unable to parse intermediate certificate 0")

	// incomplete chain of trust
	attestFails(makeData(&x509pop.AttestationData{Certificates: s.leafBundle[:1]}),
		"x509pop: certificate verification failed")

	// malformed challenge response
	challengeResponseFails("", "x509pop: unable to unmarshal challenge response")

	// invalid response
	challengeResponseFails("{}", "x509pop: challenge response verification failed")
}

func (s *Suite) TestConfigure() {
	require := s.Require()

	p := New()

	// malformed
	resp, err := p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `bad juju`,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.errorContains(err, "x509pop: unable to decode configuration")
	require.Nil(resp)

	// missing global configuration
	resp, err = p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		ca_bundle_path = "blah"
		`,
	})
	require.EqualError(err, "x509pop: global configuration is required")
	require.Nil(resp)

	// missing trust_domain
	resp, err = p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		ca_bundle_path = "blah"
		`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{},
	})
	require.EqualError(err, "x509pop: trust_domain is required")
	require.Nil(resp)

	// missing ca_bundle_path
	resp, err = p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: ``,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	require.EqualError(err, "x509pop: ca_bundle_path is required")
	require.Nil(resp)

	// bad trust bundle
	resp, err = p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		ca_bundle_path = "blah"
		`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.errorContains(err, "x509pop: unable to load trust bundle")
	require.Nil(resp)

}

func (s *Suite) TestGetPluginInfo() {
	require := s.Require()

	p := New()

	resp, err := p.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	require.NoError(err)
	require.Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *Suite) configure() {
	resp, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`
ca_bundle_path = %q
`, s.rootCertPath),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
}

func (s *Suite) attest() (nodeattestor.NodeAttestor_AttestClient, func()) {
	stream, err := s.p.Attest(context.Background())
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

func (s *Suite) errorContains(err error, substring string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), substring)
}
