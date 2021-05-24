package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	streamBuilder = nodeattestortest.ServerStream(pluginName)
)

func TestMSIAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(MSIAttestorSuite))
}

type MSIAttestorSuite struct {
	spiretest.Suite

	expectedResource string
	token            string
	tokenErr         error
}

func (s *MSIAttestorSuite) SetupTest() {
	s.expectedResource = azure.DefaultMSIResourceID
	s.token = ""
	s.tokenErr = nil
}

func (s *MSIAttestorSuite) TestAidAttestationNotConfigured() {
	attestor := s.loadAttestor()

	err := attestor.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "nodeattestor(azure_msi): not configured")
}

func (s *MSIAttestorSuite) TestAidAttestationFailedToObtainToken() {
	s.tokenErr = errors.New("FAILED")

	attestor := s.loadAttestor(plugintest.Configure(""))
	err := attestor.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatus(err, codes.Internal, "nodeattestor(azure_msi): unable to fetch token: FAILED")
}

func (s *MSIAttestorSuite) TestAidAttestationSuccess() {
	s.token = s.makeAccessToken("PRINCIPALID", "TENANTID")

	expectPayload := []byte(fmt.Sprintf(`{"token":%q}`, s.token))

	attestor := s.loadAttestor(plugintest.Configure(""))
	err := attestor.Attest(context.Background(), streamBuilder.ExpectAndBuild(expectPayload))
	s.Require().NoError(err)
}

func (s *MSIAttestorSuite) TestConfigure() {
	// malformed configuration
	var err error
	s.loadAttestor(plugintest.CaptureConfigureError(&err), plugintest.Configure("blah"))
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to decode configuration")

	// success
	s.loadAttestor(plugintest.CaptureConfigureError(&err), plugintest.Configure(""))
	s.Require().NoError(err)

	// success with resource_id
	s.loadAttestor(plugintest.CaptureConfigureError(&err), plugintest.Configure(`resource_id = "foo"`))
	s.Require().NoError(err)
}

func (s *MSIAttestorSuite) loadAttestor(options ...plugintest.Option) nodeattestor.NodeAttestor {
	p := New()
	p.hooks.fetchMSIToken = func(ctx context.Context, httpClient azure.HTTPClient, resource string) (string, error) {
		if httpClient != http.DefaultClient {
			return "", errors.New("unexpected http client")
		}
		if resource != s.expectedResource {
			return "", fmt.Errorf("expected resource %s; got %s", s.expectedResource, resource)
		}
		s.T().Logf("RETURNING %v %v", s.token, s.tokenErr)
		return s.token, s.tokenErr
	}

	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(p), attestor, options...)
	return attestor
}

func (s *MSIAttestorSuite) makeAccessToken(principalID, tenantID string) string {
	claims := azure.MSITokenClaims{
		Claims: jwt.Claims{
			Subject: principalID,
		},
		TenantID: tenantID,
	}

	signingKey := jose.SigningKey{Algorithm: jose.HS256, Key: []byte("KEY")}
	signer, err := jose.NewSigner(signingKey, nil)
	s.Require().NoError(err)

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	s.Require().NoError(err)
	return token
}
