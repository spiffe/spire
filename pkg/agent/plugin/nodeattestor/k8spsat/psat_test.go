package k8spsat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

var (
	// This is an insecure, test-only key from RFC 9500, Section 2.1.
	// It can be used in tests to avoid slow key generation.
	// See https://pkg.go.dev/crypto/rsa#example-GenerateKey-TestKey
	sampleKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
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

	streamBuilder = nodeattestortest.ServerStream(pluginName)
)

func TestAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(AttestorSuite))
}

type AttestorSuite struct {
	spiretest.Suite

	dir string
}

func (s *AttestorSuite) SetupTest() {
	s.dir = s.TempDir()
}

func (s *AttestorSuite) TestAttestNotConfigured() {
	na := s.loadPlugin()
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.T().Logf("failed: %s", err.Error())
	s.RequireGRPCStatusContains(err, codes.FailedPrecondition, "nodeattestor(k8s_psat): not configured")
}

func (s *AttestorSuite) TestAttestNoToken() {
	na := s.loadPluginWithTokenPath(s.joinPath("token"))
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "nodeattestor(k8s_psat): unable to load token from")
}

func (s *AttestorSuite) TestAttestEmptyToken() {
	na := s.loadPluginWithTokenPath(s.writeValue("token", ""))
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "nodeattestor(k8s_psat): unable to load token from")
}

func (s *AttestorSuite) TestAttestSuccess() {
	token, err := createPSAT("NAMESPACE", "POD-NAME")
	s.Require().NoError(err)

	na := s.loadPluginWithTokenPath(s.writeValue("token", token))

	err = na.Attest(context.Background(), streamBuilder.ExpectAndBuild([]byte(fmt.Sprintf(`{"cluster":"production","token":"%s"}`, token))))
	s.Require().NoError(err)
}

func (s *AttestorSuite) TestConfigure() {
	var err error

	// malformed configuration
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure("malformed"),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to decode configuration")

	// missing cluster
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(""),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "missing required cluster block")

	// success
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`cluster = "production"`),
	)
	s.Require().NoError(err)
}

func (s *AttestorSuite) loadPluginWithTokenPath(tokenPath string) nodeattestor.NodeAttestor {
	return s.loadPlugin(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configuref(`
			cluster = "production"
			token_path = %q
		`, tokenPath),
	)
}

func (s *AttestorSuite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), na, options...)
	return na
}

func (s *AttestorSuite) joinPath(path string) string {
	return filepath.Join(s.dir, path)
}

func (s *AttestorSuite) writeValue(path, data string) string {
	valuePath := s.joinPath(path)
	err := os.MkdirAll(filepath.Dir(valuePath), 0o755)
	s.Require().NoError(err)
	err = os.WriteFile(valuePath, []byte(data), 0o600)
	s.Require().NoError(err)
	return valuePath
}

// Creates a PSAT using the given namespace and podName (just for testing)
func createPSAT(namespace, podName string) (string, error) {
	// Create a jwt builder
	s, err := createSigner()
	if err != nil {
		return "", err
	}

	builder := jwt.Signed(s)

	// Set useful claims for testing
	claims := sat_common.PSATClaims{}
	claims.K8s.Namespace = namespace
	claims.K8s.Pod.Name = podName
	builder = builder.Claims(claims)

	// Serialize and return token
	token, err := builder.Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

func createSigner() (jose.Signer, error) {
	sampleKey, err := pemutil.ParseRSAPrivateKey(sampleKeyPEM)
	if err != nil {
		return nil, err
	}

	sampleSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       sampleKey,
	}, nil)
	if err != nil {
		return nil, err
	}

	return sampleSigner, nil
}
