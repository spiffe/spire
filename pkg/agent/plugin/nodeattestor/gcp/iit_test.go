package gcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/stretchr/testify/suite"
)

func TestIITAttestorPlugin(t *testing.T) {
	suite.Run(t, new(Suite))
}

type Suite struct {
	suite.Suite

	p      *nodeattestor.BuiltIn
	server *httptest.Server
	status int
	body   string
}

func (s *Suite) SetupTest() {
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "unexpected flavor", http.StatusInternalServerError)
			return
		}
		if req.URL.Path != identityTokenURLPath {
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		if req.URL.Query().Get("audience") != identityTokenAudience {
			http.Error(w, "unexpected audience", http.StatusInternalServerError)
			return
		}
		if req.URL.Query().Get("format") != "full" {
			http.Error(w, "unexpected format", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(s.status)
		w.Write([]byte(s.body))
	}))

	p := NewIITAttestorPlugin()
	p.tokenHost = s.server.Listener.Addr().String()

	s.p = nodeattestor.NewBuiltIn(p)
	_, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `trust_domain = "example.org"`,
	})
	s.Require().NoError(err)
	s.status = http.StatusOK
}

func (s *Suite) TearDownTest() {
	s.server.Close()
}

func (s *Suite) TestErrorWhenNotConfigured() {
	p := nodeattestor.NewBuiltIn(NewIITAttestorPlugin())
	stream, err := p.FetchAttestationData(context.Background())
	defer stream.CloseSend()
	resp, err := stream.Recv()
	s.requireErrorContains(err, "gcp-iit: not configured")
	s.Require().Nil(resp)
}

func (s *Suite) TestUnexpectedStatus() {
	s.status = http.StatusBadGateway
	s.body = ""
	_, err := s.fetchAttestationData()
	s.requireErrorContains(err, "gcp-iit: unable to retrieve identity token: unexpected status code: 502")
}

func (s *Suite) TestErrorOnInvalidToken() {
	s.body = "invalid"
	_, err := s.fetchAttestationData()
	s.requireErrorContains(err, "gcp-iit: unable to parse identity token: token contains an invalid number of segments")
}

func (s *Suite) TestErrorOnMissingClaimsInIdentityToken() {
	token := jwt.New(jwt.SigningMethodHS256)
	s.body = s.signToken(token)
	_, err := s.fetchAttestationData()
	s.requireErrorContains(err, "gcp-iit: identity token is missing google claims")
}

func (s *Suite) TestSuccessfulIdentityTokenProcessing() {
	require := s.Require()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"google": gcp.Google{
			ComputeEngine: gcp.ComputeEngine{
				ProjectID:  "project-123",
				InstanceID: "instance-123",
			},
		},
	})
	s.body = s.signToken(token)
	resp, err := s.fetchAttestationData()
	require.NoError(err)
	require.NotNil(resp)
	require.Equal("spiffe://example.org/spire/agent/gcp_iit/project-123/instance-123", resp.SpiffeId)
	require.Equal(gcp.PluginName, resp.AttestationData.Type)
	require.Equal(s.body, string(resp.AttestationData.Data))
}

func (s *Suite) TestConfigure() {
	require := s.Require()

	// malformed
	resp, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `trust_domain`,
	})
	require.Error(err)
	require.Nil(resp)

	// missing trust domain
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.requireErrorContains(err, "gcp-iit: trust_domain is required")
	require.Nil(resp)

	// success
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `trust_domain = "example.org"`,
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

func (s *Suite) signToken(token *jwt.Token) string {
	tokenString, err := token.SignedString([]byte("secret"))
	s.NoError(err)
	return tokenString
}

func (s *Suite) requireErrorContains(err error, substring string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), substring)
}
