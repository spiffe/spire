package azure

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestMSIAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(MSIAttestorSuite))
}

type MSIAttestorSuite struct {
	spiretest.Suite

	attestor nodeattestor.Plugin

	expectedResource string
	token            string
	tokenErr         error
}

func (s *MSIAttestorSuite) SetupTest() {
	s.expectedResource = azure.DefaultMSIResourceID
	s.token = ""
	s.tokenErr = nil

	s.newAttestor()

	_, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{
			TrustDomain: "example.org",
		},
	})
	s.Require().NoError(err)
}

func (s *MSIAttestorSuite) TestFetchAttestationDataNotConfigured() {
	s.newAttestor()
	s.requireFetchError("azure-msi: not configured")
}

func (s *MSIAttestorSuite) TestFetchAttestationDataFailedToObtainToken() {
	s.tokenErr = errors.New("FAILED")
	s.requireFetchError("azure-msi: unable to fetch token: FAILED")
}

func (s *MSIAttestorSuite) TestFetchAttestationDataSuccess() {
	s.token = s.makeAccessToken("PRINCIPALID", "TENANTID")

	stream, err := s.attestor.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().NotNil(resp)

	// assert attestation data
	s.Require().NotNil(resp.AttestationData)
	s.Require().Equal("azure_msi", resp.AttestationData.Type)
	s.Require().JSONEq(fmt.Sprintf(`{"token": %q}`, s.token), string(resp.AttestationData.Data))

	// node attestor should return EOF now
	_, err = stream.Recv()
	s.Require().Equal(io.EOF, err)
}

func (s *MSIAttestorSuite) TestConfigure() {
	// malformed configuration
	resp, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: "blah",
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{},
	})
	s.RequireGRPCStatusContains(err, codes.Unknown, "azure-msi: unable to decode configuration")
	s.Require().Nil(resp)

	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.RequireGRPCStatusContains(err, codes.Unknown, "azure-msi: global configuration is required")
	s.Require().Nil(resp)

	// missing trust domain
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{}})
	s.RequireGRPCStatus(err, codes.Unknown, "azure-msi: global configuration missing trust domain")
	s.Require().Nil(resp)

	// success
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
}

func (s *MSIAttestorSuite) TestGetPluginInfo() {
	resp, err := s.attestor.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *MSIAttestorSuite) newAttestor() {
	attestor := New()
	attestor.hooks.fetchMSIToken = func(ctx context.Context, httpClient azure.HTTPClient, resource string) (string, error) {
		if httpClient != http.DefaultClient {
			return "", errors.New("unexpected http client")
		}
		if resource != s.expectedResource {
			return "", fmt.Errorf("expected resource %s; got %s", s.expectedResource, resource)
		}
		s.T().Logf("RETURNING %v %v", s.token, s.tokenErr)
		return s.token, s.tokenErr
	}
	s.LoadPlugin(builtin(attestor), &s.attestor)
}

func (s *MSIAttestorSuite) requireFetchError(contains string) {
	stream, err := s.attestor.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	resp, err := stream.Recv()
	s.RequireErrorContains(err, contains)
	s.Require().Nil(resp)
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
