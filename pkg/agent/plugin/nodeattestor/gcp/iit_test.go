package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

const testServiceAccount = "test-service-account"

func TestIITAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	p      nodeattestor.Plugin
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
		if req.URL.Path != fmt.Sprintf(identityTokenURLPathTemplate, testServiceAccount) {
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
		_, _ = w.Write([]byte(s.body))
	}))

	s.p = s.newPlugin()
	s.configure()
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
	s.requireErrorContains(err, "gcp-iit: not configured")
	s.Require().Nil(resp)
}

func (s *Suite) TestUnexpectedStatus() {
	s.status = http.StatusBadGateway
	s.body = ""
	_, err := s.fetchAttestationData()
	s.requireErrorContains(err, "gcp-iit: unable to retrieve valid identity token: unexpected status code: 502")
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
	require.Equal(gcp.PluginName, resp.AttestationData.Type)
	require.Equal(s.body, string(resp.AttestationData.Data))
}

func (s *Suite) TestFailToSendOnStream() {
	require := s.Require()

	p := New()
	_, err := p.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{
			TrustDomain: "example.org",
		},
		Configuration: fmt.Sprintf(`
service_account = "%s"
identity_token_host = "%s"
`, testServiceAccount, s.server.Listener.Addr().String()),
	})
	require.NoError(err)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"google": gcp.Google{
			ComputeEngine: gcp.ComputeEngine{
				ProjectID:  "project-123",
				InstanceID: "instance-123",
			},
		},
	})
	s.body = s.signToken(token)
	err = p.FetchAttestationData(&failSendStream{})
	require.EqualError(err, "failed to send to stream")
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

	// global configuration not provided
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.requireErrorContains(err, "gcp-iit: global configuration is required")
	require.Nil(resp)

	// missing trust domain
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{}})
	s.requireErrorContains(err, "gcp-iit: trust_domain is required")
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
	p := New()

	var plugin nodeattestor.Plugin
	s.LoadPlugin(builtin(p), &plugin)
	return plugin
}

func (s *Suite) configure() {
	_, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{
			TrustDomain: "example.org",
		},
		Configuration: fmt.Sprintf(`
service_account = "%s"
identity_token_host = "%s"
`, testServiceAccount, s.server.Listener.Addr().String()),
	})
	s.Require().NoError(err)
	s.status = http.StatusOK
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

func TestRetrieveIdentity(t *testing.T) {
	tests := []struct {
		msg               string
		url               string
		handleFunc        func(w http.ResponseWriter, req *http.Request)
		expectErrContains string
	}{
		{
			msg:               "bad url",
			url:               "::",
			expectErrContains: "missing protocol scheme",
		},
		{
			msg:               "invalid port",
			url:               "http://0.0.0.0:70000",
			expectErrContains: "invalid port",
		},
		{
			msg: "fail to read body",
			handleFunc: func(w http.ResponseWriter, req *http.Request) {
				// Set a content length but don't write a body
				w.Header().Set("Content-Length", "40")
				w.WriteHeader(http.StatusOK)
			},
			expectErrContains: "unexpected EOF",
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.msg, func(t *testing.T) {
			url := tt.url
			if tt.handleFunc != nil {
				server := httptest.NewServer(http.HandlerFunc(tt.handleFunc))
				url = server.URL
				defer server.Close()
			}

			_, err := retrieveInstanceIdentityToken(url)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectErrContains)
		})
	}
}

type failSendStream struct {
	nodeattestor.NodeAttestor_FetchAttestationDataServer
}

func (s *failSendStream) Send(*nodeattestor.FetchAttestationDataResponse) error {
	return errors.New("failed to send to stream")
}
