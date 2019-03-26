package aws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/spire/pkg/common/pemutil"

	"github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/stretchr/testify/suite"
)

const (
	defaultIdentityDocumentPath  = "/latest/dynamic/instance-identity/document"
	defaultIdentitySignaturePath = "/latest/dynamic/instance-identity/signature"
)

var (
	signingKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAOn4rFLlxONpujl+q/h/kTQzZoqn1nQZbCKEyIPBWO6kkcSqIqON
aB3i+xyxgZNwkGEkLGRl/Uwasbp7O/sU43wh5ywWp/AG0iFe1RhwMd8LMq5ron6o
s2eql71hJKsGEwIDAQABAmEAoDa9YcKe8Q68C5TXE8He33z3Ealea3/hET4VxEsI
p9mfS6kpMQ+qpRSB2aMfVKP1mrAQ4/5TarrG1ZG3T/Mt9Oy1QHbzALvz2XObIvcR
0cnG353CLQK/nobvWcwAtac5AjEA9k+1a9R6eFaO3grl9yg5XY2+MboV4wjbsDS3
s4+MivneTPwvK6eHxtoAlYCNOAslAjEA8yy0PJw3TLBK80DryF3r/Q4wd4uYeFhN
G6EBF0LccLB7GbKpcDHgnNjW/wObx+LXAjBeP4/G6+3U4CIYuojWMvEIaDVPp8m6
LuiJGxLzxUjc4NF8Gb8e8CLXJxG0IxVmTXUCMQDSPJAG5rgYoUHrVPGEZU8llSLp
99J2GUFw5Z3f0nprIukKqqA606RxdjdKeoAwLDkCMCptc0jZR3VM4w1wnwvAe0FL
t61Ol/Q+OqWFX74JwsUU56FqPFm3Y9k7HxDILdedoQ==
-----END RSA PRIVATE KEY-----`)
)

func TestIIDAttestorPlugin(t *testing.T) {
	suite.Run(t, new(Suite))
}

type Suite struct {
	suite.Suite

	p       *nodeattestor.BuiltIn
	server  *httptest.Server
	status  int
	docBody string
	sigBody string
}

func (s *Suite) SetupTest() {
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch path := req.URL.Path; path {
		case defaultIdentityDocumentPath:
			// write doc resp
			w.WriteHeader(s.status)
			w.Write([]byte(s.docBody))
		case defaultIdentitySignaturePath:
			// write sig resp
			w.WriteHeader(s.status)
			w.Write([]byte(s.sigBody))
		default:
			// unexpected path
			w.WriteHeader(http.StatusForbidden)
		}
	}))

	p := NewIIDPlugin()

	s.p = nodeattestor.NewBuiltIn(p)
	_, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`
identity_document_url = "http://%s%s"
identity_signature_url = "http://%s%s"
`, s.server.Listener.Addr().String(), defaultIdentityDocumentPath, s.server.Listener.Addr().String(), defaultIdentitySignaturePath),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{
			TrustDomain: "example.org",
		},
	})
	s.Require().NoError(err)

	s.status = http.StatusOK
}

func (s *Suite) TearDownTest() {
	s.server.Close()
}

func (s *Suite) TestErrorWhenNotConfigured() {
	p := nodeattestor.NewBuiltIn(NewIIDPlugin())
	stream, err := p.FetchAttestationData(context.Background())
	defer stream.CloseSend()
	resp, err := stream.Recv()
	s.requireErrorContains(err, "not configured")
	s.Require().Nil(resp)
}

func (s *Suite) TestUnexpectedStatus() {
	s.status = http.StatusBadGateway
	s.docBody = ""
	_, err := s.fetchAttestationData()
	s.requireErrorContains(err, "unexpected status code: 502")
}

func (s *Suite) TestEmptyDoc() {
	s.docBody = ""
	_, err := s.fetchAttestationData()
	s.requireErrorContains(err, "unexpected end of JSON input")
}

func (s *Suite) TestErrorOnInvalidDoc() {
	s.docBody = "invalid"
	_, err := s.fetchAttestationData()
	s.requireErrorContains(err, "error occurred unmarshaling the IID")
}

func (s *Suite) TestSuccessfulIdentityProcessing() {
	doc, sig := s.buildDefaultIIDDocAndSig()
	s.docBody = string(doc)
	s.sigBody = string(sig)
	require := s.Require()

	// default template
	resp, err := s.fetchAttestationData()
	require.NoError(err)
	require.NotNil(resp)
	require.Equal("spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance", resp.SpiffeId)
	require.Equal(aws.PluginName, resp.AttestationData.Type)
	expectedBytes, err := json.Marshal(aws.IIDAttestationData{
		Document:  string(doc),
		Signature: string(sig),
	})
	require.NoError(err)
	require.Equal(string(expectedBytes), string(resp.AttestationData.Data))

	// change in template
	_, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: fmt.Sprintf(`
agent_path_template = "{{ .AccountID }}/{{ .Region }}/{{ .InstanceID }}/{{ .PluginName}}"
identity_document_url = "http://%s%s"
identity_signature_url = "http://%s%s"
`, s.server.Listener.Addr().String(), defaultIdentityDocumentPath, s.server.Listener.Addr().String(), defaultIdentitySignaturePath),
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{
			TrustDomain: "example.org",
		},
	})
	s.Require().NoError(err)
	resp, err = s.fetchAttestationData()
	require.NoError(err)
	require.NotNil(resp)
	require.Equal("spiffe://example.org/spire/agent/test-account/test-region/test-instance/aws_iid", resp.SpiffeId)
	require.Equal(aws.PluginName, resp.AttestationData.Type)
	expectedBytes, err = json.Marshal(aws.IIDAttestationData{
		Document:  string(doc),
		Signature: string(sig),
	})
	require.NoError(err)
	require.Equal(string(expectedBytes), string(resp.AttestationData.Data))
}

func (s *Suite) TestConfigure() {
	require := s.Require()

	// malformed
	resp, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{},
		Configuration: `trust_domain`,
	})
	require.Error(err)
	require.Nil(resp)

	// global configuration not provided
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.requireErrorContains(err, "global configuration is required")
	require.Nil(resp)

	// missing trust domain
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{}})
	s.requireErrorContains(err, "global configuration missing trust domain")
	require.Nil(resp)

	// success
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{
			TrustDomain: "example.org",
		},
	})
	require.NoError(err)
	require.NotNil(resp)
	require.Equal(resp, &plugin.ConfigureResponse{})
}

func (s *Suite) TestGetPluginInfo() {
	require := s.Require()
	resp, err := s.p.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	require.NoError(err)
	require.NotNil(resp)
	require.Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *Suite) fetchAttestationData() (*nodeattestor.FetchAttestationDataResponse, error) {
	stream, err := s.p.FetchAttestationData(context.Background())
	s.NoError(err)
	s.NoError(stream.CloseSend())
	return stream.Recv()
}

func (s *Suite) requireErrorContains(err error, substring string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), substring)
}

func (s *Suite) buildDefaultIIDDocAndSig() (docBytes []byte, sigBytes []byte) {
	// doc body
	doc := aws.InstanceIdentityDocument{
		AccountID:  "test-account",
		InstanceID: "test-instance",
		Region:     "test-region",
	}
	docBytes, err := json.Marshal(doc)
	s.Require().NoError(err)

	rng := rand.Reader
	key, err := pemutil.ParseRSAPrivateKey(signingKeyPEM)
	s.Require().NoError(err)

	// doc signature
	docHash := sha256.Sum256(docBytes)
	sig, err := rsa.SignPKCS1v15(rng, key, crypto.SHA256, docHash[:])
	s.Require().NoError(err)

	return docBytes, sig
}
