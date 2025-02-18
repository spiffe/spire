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
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
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
	// This is an insecure, test-only key from RFC 9500, Section 2.1.
	// It can be used in tests to avoid slow key generation.
	// See https://pkg.go.dev/crypto/rsa#example-GenerateKey-TestKey
	signingKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
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
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
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
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.CaptureConfigureError(&err),
		plugintest.Configure("malformed"),
	)
	require.Error(err)

	// success
	s.loadPlugin(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(""),
	)
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
