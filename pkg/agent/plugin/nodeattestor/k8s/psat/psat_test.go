package psat

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/pemutil"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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

func TestAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(AttestorSuite))
}

type AttestorSuite struct {
	spiretest.Suite

	dir      string
	attestor nodeattestor.Plugin
}

func (s *AttestorSuite) SetupTest() {
	s.dir = s.TempDir()

	s.newAttestor()
	s.configure(AttestorConfig{})
}

func (s *AttestorSuite) TestFetchAttestationDataNotConfigured() {
	s.newAttestor()
	s.requireFetchError("k8s-psat: not configured")
}

func (s *AttestorSuite) TestFetchAttestationDataNoToken() {
	s.configure(AttestorConfig{
		TokenPath: s.joinPath("token"),
	})
	s.requireFetchError("unable to load token from")
}

func (s *AttestorSuite) TestFetchAttestationDataSuccess() {
	token, err := createPSAT("NAMESPACE", "POD-NAME")
	s.Require().NoError(err)

	s.configure(AttestorConfig{
		TokenPath: s.writeValue("token", token),
	})

	stream, err := s.attestor.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().NotNil(resp)

	// assert attestation data
	s.Require().NotNil(resp.AttestationData)
	s.Require().Equal("k8s_psat", resp.AttestationData.Type)
	s.Require().JSONEq(fmt.Sprintf(`{
		"cluster": "production",
		"token": "%s"
	}`, token), string(resp.AttestationData.Data))

	// node attestor should return EOF now
	_, err = stream.Recv()
	s.Require().Equal(io.EOF, err)
}

func (s *AttestorSuite) TestConfigure() {
	// malformed configuration
	resp, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{},
		Configuration: "blah",
	})
	s.RequireGRPCStatusContains(err, codes.Unknown, "k8s-psat: unable to decode configuration")
	s.Require().Nil(resp)

	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.RequireGRPCStatusContains(err, codes.Unknown, "k8s-psat: global configuration is required")
	s.Require().Nil(resp)

	// missing trust domain
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{}})
	s.RequireGRPCStatus(err, codes.Unknown, "k8s-psat: global configuration missing trust domain")
	s.Require().Nil(resp)

	// missing cluster
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.RequireGRPCStatus(err, codes.Unknown, "k8s-psat: configuration missing cluster")
	s.Require().Nil(resp)

	// success
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
		Configuration: `cluster = "production"`,
	})
	s.Require().NoError(err)
	s.RequireProtoEqual(resp, &plugin.ConfigureResponse{})
}

func (s *AttestorSuite) TestGetPluginInfo() {
	resp, err := s.attestor.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.RequireProtoEqual(resp, &plugin.GetPluginInfoResponse{})
}

func (s *AttestorSuite) newAttestor() {
	attestor := New()
	s.LoadPlugin(builtin(attestor), &s.attestor)
}

func (s *AttestorSuite) configure(config AttestorConfig) {
	_, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{
			TrustDomain: "example.org",
		},
		Configuration: fmt.Sprintf(`
			cluster = "production"
			token_path = %q`, config.TokenPath),
	})
	s.Require().NoError(err)
}

func (s *AttestorSuite) joinPath(path string) string {
	return filepath.Join(s.dir, path)
}

func (s *AttestorSuite) writeValue(path, data string) string {
	valuePath := s.joinPath(path)
	err := os.MkdirAll(filepath.Dir(valuePath), 0755)
	s.Require().NoError(err)
	err = ioutil.WriteFile(valuePath, []byte(data), 0600)
	s.Require().NoError(err)
	return valuePath
}

func (s *AttestorSuite) requireFetchError(contains string) {
	stream, err := s.attestor.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	resp, err := stream.Recv()
	s.RequireErrorContains(err, contains)
	s.Require().Nil(resp)
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
