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

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
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
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	p       nodeattestor.Plugin
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
			_, _ = w.Write([]byte(s.docBody))
		case defaultIdentitySignaturePath:
			// write sig resp
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(s.sigBody))
		default:
			// unexpected path
			w.WriteHeader(http.StatusForbidden)
		}
	}))

	s.p = s.newPlugin()

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
	p := s.newPlugin()
	stream, err := p.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	defer func() {
		s.Require().NoError(stream.CloseSend())
	}()
	resp, err := stream.Recv()
	s.RequireErrorContains(err, "not configured")
	s.Require().Nil(resp)
}

func (s *Suite) TestUnexpectedStatus() {
	s.status = http.StatusBadGateway
	s.docBody = ""
	_, err := s.fetchAttestationData()
	s.RequireErrorContains(err, "unexpected status code: 502")
}

func (s *Suite) TestSuccessfulIdentityProcessing() {
	doc, sig := s.buildDefaultIIDDocAndSig()
	s.docBody = string(doc)
	s.sigBody = string(sig)
	require := s.Require()

	resp, err := s.fetchAttestationData()
	require.NoError(err)
	require.NotNil(resp)
	require.Equal(aws.PluginName, resp.AttestationData.Type)
	expectedBytes, err := json.Marshal(aws.IIDAttestationData{
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

func (s *Suite) newPlugin() nodeattestor.Plugin {
	var p nodeattestor.Plugin
	s.LoadPlugin(BuiltIn(), &p)
	return p
}

func (s *Suite) fetchAttestationData() (*nodeattestor.FetchAttestationDataResponse, error) {
	stream, err := s.p.FetchAttestationData(context.Background())
	s.NoError(err)
	s.NoError(stream.CloseSend())
	return stream.Recv()
}

func (s *Suite) buildDefaultIIDDocAndSig() (docBytes []byte, sigBytes []byte) {
	// doc body
	doc := ec2metadata.EC2InstanceIdentityDocument{
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
