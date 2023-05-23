package awsiid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/fullsailor/pkcs7"
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
	identitySignatureRSA1024Path = "/latest/dynamic/instance-identity/signature"
	identitySignatureRSA2048Path = "/latest/dynamic/instance-identity/rsa2048"
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

	p              nodeattestor.NodeAttestor
	server         *httptest.Server
	status         int
	docBody        string
	sigRSA1024Body string
	sigRSA2048Body string
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
		case identitySignatureRSA1024Path:
			// write sigRSA1024 resp
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(s.sigRSA1024Body))
		case identitySignatureRSA2048Path:
			// write sigRSA1024 resp
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(s.sigRSA2048Body))
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
	doc, sigRSA1024, sigRSA2048 := s.buildDefaultIIDDocAndSig()
	s.docBody = string(doc)
	s.sigRSA1024Body = string(sigRSA1024)
	s.sigRSA2048Body = base64.StdEncoding.EncodeToString(sigRSA2048)

	require := s.Require()

	expectPayload, err := json.Marshal(aws.IIDAttestationData{
		Document:         string(doc),
		Signature:        string(sigRSA1024),
		SignatureRSA2048: base64.StdEncoding.EncodeToString(sigRSA2048),
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

func (s *Suite) buildDefaultIIDDocAndSig() (docBytes []byte, sigBytes []byte, sigRSA2048 []byte) {
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

	sigRSA2048 = s.generatePKCS7Signature(docBytes, key)

	return docBytes, sig, sigRSA2048
}

func (s *Suite) generatePKCS7Signature(docBytes []byte, key *rsa.PrivateKey) []byte {
	signedData, err := pkcs7.NewSignedData(docBytes)
	s.Require().NoError(err)

	cert := s.generateCertificate(key)
	privateKey := crypto.PrivateKey(key)
	err = signedData.AddSigner(cert, privateKey, pkcs7.SignerInfoConfig{})
	s.Require().NoError(err)

	signature, err := signedData.Finish()
	s.Require().NoError(err)

	return signature
}

func (s *Suite) generateCertificate(key crypto.Signer) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	s.Require().NoError(err)

	cert, err := x509.ParseCertificate(certDER)
	s.Require().NoError(err)

	return cert
}
