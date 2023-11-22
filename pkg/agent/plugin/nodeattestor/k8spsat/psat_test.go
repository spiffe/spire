package k8spsat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/pemutil"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

var sampleKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAMB4gbT09H2RKXaxbu6IV9C3WY+pvkGAbrlQRIHLHwV3Xt1HchjX
c08v1VEoTBN2YTjhZJlDb/VUsNMJsmBFBBted5geRcbrDtXFlUJ8tQoQx1dWM4Aa
xcdULJ83A9ICKwIDAQABAmBR1asInrIphYQEtHJ/NzdnRd3tqHV9cjch0dAfA5dA
Ar4yBYOsrkaX37WqWSDnkYgN4FWYBWn7WxeotCtA5UQ3SM5hLld67rUqAm2dLrs1
z8va6SwLzrPTu2+rmRgovFECMQDpbfPBRex7FY/xWu1pYv6X9XZ26SrC2Wc6RIpO
38AhKGjTFEMAPJQlud4e2+4I3KkCMQDTFLUvBSXokw2NvcNiM9Kqo5zCnCIkgc+C
hM3EzSh2jh4gZvRzPOhXYvNKgLx8+LMCMQDL4meXlpV45Fp3eu4GsJqi65jvP7VD
v1P0hs0vGyvbSkpUo0vqNv9G/FNQLNR6FRECMFXEMz5wxA91OOuf8HTFg9Lr+fUl
RcY5rJxm48kUZ12Mr3cQ/kCYvftL7HkYR/4rewIxANdritlIPu4VziaEhYZg7dvz
pG3eEhiqPxE++QHpwU78O+F1GznOPBvpZOB3GfyjNQ==
-----END RSA PRIVATE KEY-----`)

var (
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
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "nodeattestor(k8s_psat): not configured")
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
	s.loadPlugin(plugintest.CaptureConfigureError(&err), plugintest.Configure("malformed"))
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to decode configuration")

	// missing cluster
	s.loadPlugin(plugintest.CaptureConfigureError(&err), plugintest.Configure(""))
	s.RequireGRPCStatus(err, codes.InvalidArgument, "configuration missing cluster")

	// success
	s.loadPlugin(plugintest.CaptureConfigureError(&err), plugintest.Configure(`cluster = "production"`))
	s.Require().NoError(err)
}

func (s *AttestorSuite) loadPluginWithTokenPath(tokenPath string) nodeattestor.NodeAttestor {
	return s.loadPlugin(plugintest.Configuref(`
			cluster = "production"
			token_path = %q
	`, tokenPath))
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
	err := os.MkdirAll(filepath.Dir(valuePath), 0755)
	s.Require().NoError(err)
	err = os.WriteFile(valuePath, []byte(data), 0600)
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
	token, err := builder.CompactSerialize()
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
