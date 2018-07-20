package k8s

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/suite"
)

const (
	trustDomain = "example.org"
)

func (s *Suite) attest() (nodeattestor.Attest_Stream, func()) {
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

func TestK8sAttestor(t *testing.T) {
	suite.Run(t, new(Suite))
}

type Suite struct {
	suite.Suite

	p      *nodeattestor.BuiltIn
	idKey  crypto.PrivateKey
	idDoc  *x509.Certificate
	caCert *x509.Certificate
}

func (s *Suite) SetupTest() {
	require := s.Require()
	idDocPath := fixture.Join("nodeattestor", "k8s", "id-doc.pem")
	idKeyPath := fixture.Join("nodeattestor", "k8s", "id-key.pem")
	caBundlePath := fixture.Join("nodeattestor", "k8s", "k8s-ca.pem")

	s.p = nodeattestor.NewBuiltIn(New())
	config := &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`
			trust_domain = %q
			ca_bundle_path = %q`,
			trustDomain, caBundlePath),
	}

	resp, err := s.p.Configure(context.Background(), config)
	require.NoError(err)
	require.Equal(resp, &plugin.ConfigureResponse{})

	kp, err := tls.LoadX509KeyPair(idDocPath, idKeyPath)
	require.NoError(err)
	s.idKey = kp.PrivateKey
	s.idDoc, err = x509.ParseCertificate(kp.Certificate[0])
	s.caCert, err = util.LoadCert(caBundlePath)
	require.NoError(err)
}

func (s *Suite) TestConfigure() {
	require := s.Require()

	type testParam struct {
		trustDomain  string
		caBundlePath string
		expectedErr  string
	}

	// negative test cases
	testCases := []testParam{
		{"", "cabp", "trust_domain is required"},
		{"td", "", "ca_bundle_path is required"},
		{"td", "cabp", "unable to load trust bundle"},
	}

	for _, t := range testCases {
		p := nodeattestor.NewBuiltIn(New())
		config := fmt.Sprintf(`
			trust_domain = %q
			ca_bundle_path = %q`,
			t.trustDomain, t.caBundlePath)

		resp, err := p.Configure(context.Background(), &plugin.ConfigureRequest{
			Configuration: config,
		})
		s.errorContains(err, t.expectedErr)
		require.Nil(resp)
	}
}

func (s *Suite) TestGetPluginInfo() {
	require := s.Require()

	p := New()

	resp, err := p.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	require.NoError(err)
	require.Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *Suite) TestAttestSuccess() {
	require := s.Require()

	stream, done := s.attest()
	defer done()

	// send down good attestation data
	attestationData := &x509pop.AttestationData{
		Certificates: [][]byte{s.idDoc.Raw},
	}
	err := stream.Send(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "k8s",
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
	response, err := x509pop.CalculateResponse(s.idKey, challenge)
	require.NoError(err)
	err = stream.Send(&nodeattestor.AttestRequest{
		Response: s.marshal(response),
	})
	require.NoError(err)

	// receive the attestation result
	resp, err = stream.Recv()
	require.NoError(err)
	s.True(resp.Valid)
	agentID := strings.Replace(s.idDoc.Subject.CommonName, ":", "/", -1)
	require.Equal("spiffe://"+trustDomain+"/spire/agent/k8s/"+agentID, resp.BaseSPIFFEID)
	require.Nil(resp.Challenge)
	require.Len(resp.Selectors, 2)
	require.EqualValues([]*common.Selector{
		{Type: "k8s", Value: "subject:cn:system:node:node1"},
		{Type: "k8s", Value: "ca:fingerprint:" + x509pop.Fingerprint(s.caCert)},
	}, resp.Selectors)
}

func (s *Suite) TestAttestFailure() {
	require := s.Require()

	makeData := func(attestationData *x509pop.AttestationData) *common.AttestationData {
		return &common.AttestationData{
			Type: "k8s",
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
				Certificates: [][]byte{s.idDoc.Raw},
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
	stream, err := nodeattestor.NewBuiltIn(New()).Attest(context.Background())
	require.NoError(err)
	defer stream.CloseSend()
	require.NoError(stream.Send(&nodeattestor.AttestRequest{}))
	_, err = stream.Recv()
	require.EqualError(err, "k8s node attestor: not configured")

	// unexpected data type
	attestFails(&common.AttestationData{Type: "foo"},
		"k8s node attestor: unexpected attestation data type \"foo\"")

	// malformed data
	attestFails(&common.AttestationData{Type: "k8s"},
		"k8s node attestor: failed to unmarshal data")

	// no identity doc
	attestFails(makeData(&x509pop.AttestationData{}),
		"k8s node attestor: no certificate to attest")

	// malformed identity doc
	attestFails(makeData(&x509pop.AttestationData{Certificates: [][]byte{{0x00}}}),
		"k8s node attestor: unable to parse leaf certificate")

	// identity doc signed by unknown authority
	unauthCertPath := fixture.Join("nodeattestor", "x509pop", "root-crt.pem")
	unauthCert, err := util.LoadCert(unauthCertPath)
	require.NoError(err)
	attestFails(makeData(&x509pop.AttestationData{Certificates: [][]byte{unauthCert.Raw}}),
		"k8s node attestor: certificate verification failed")

	// malformed challenge response
	challengeResponseFails("", "k8s node attestor: unable to unmarshal challenge response")

	// invalid response
	challengeResponseFails("{}", "k8s node attestor: challenge response verification failed")
}
