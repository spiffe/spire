package awsiid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

const (
	apiTokenPath                 = "/latest/api/token"   //nolint: gosec // false positive
	staticToken                  = "It's just some data" //nolint: gosec // false positive
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

	streamBuilder = nodeattestortest.ServerStream(aws.PluginName)
)

func TestIIDAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	p       nodeattestor.NodeAttestor
	server  *httptest.Server
	status  int
	docBody string
	sigBody string
}

func (s *Suite) SetupTest() {
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch path := req.URL.Path; path {
		case apiTokenPath:
			// Token requested by AWS SDK for IMDSv2 authentication
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(staticToken))
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

	s.p = s.loadPlugin(
		plugintest.Configuref(`ec2_metadata_endpoint = "http://%s/latest"`, s.server.Listener.Addr()),
	)

	s.status = http.StatusOK
}

func (s *Suite) TearDownTest() {
	s.server.Close()
}

func (s *Suite) TestErrorWhenNotConfigured() {
	p := s.loadPlugin()

	err := p.Attest(context.Background(), nil)
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "nodeattestor(aws_iid): not configured")
}

func (s *Suite) TestUnexpectedStatus() {
	s.status = http.StatusBadGateway
	s.docBody = ""
	err := s.p.Attest(context.Background(), streamBuilder.Build())
	s.RequireErrorContains(err, "StatusCode: 502")
}

func (s *Suite) TestSuccessfulIdentityProcessing() {
	doc, sig := s.buildDefaultIIDDocAndSig()
	s.docBody = string(doc)
	s.sigBody = string(sig)

	require := s.Require()

	expectPayload, err := json.Marshal(aws.IIDAttestationData{
		Document:  string(doc),
		Signature: string(sig),
	})
	require.NoError(err)

	err = s.p.Attest(context.Background(), streamBuilder.ExpectAndBuild(expectPayload))
	require.NoError(err)
}

func (s *Suite) TestConfigure() {
	require := s.Require()

	var err error
	s.loadPlugin(
		plugintest.CaptureConfigureError(&err),
		plugintest.Configure("malformed"),
	)
	require.Error(err)

	// success
	s.loadPlugin(plugintest.Configure(""))
}

func (s *Suite) loadPlugin(opts ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), na, opts...)
	return na
}

func (s *Suite) buildDefaultIIDDocAndSig() (docBytes []byte, sigBytes []byte) {
	// doc body
	doc := imds.InstanceIdentityDocument{
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
