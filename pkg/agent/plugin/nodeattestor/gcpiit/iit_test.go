package gcpiit

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const testServiceAccount = "test-service-account"

var (
	streamBuilder = nodeattestortest.ServerStream(gcp.PluginName)
)

func TestIITAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	na     nodeattestor.NodeAttestor
	server *httptest.Server
	status int
	body   string
}

func (s *Suite) SetupSuite() {
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
}

func (s *Suite) SetupTest() {
	s.status = http.StatusOK
	s.body = ""
	s.na = s.loadPlugin(plugintest.CoreConfig(catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}),
		plugintest.Configuref(`
		service_account = "%s"
		identity_token_host = "%s"
`, testServiceAccount, s.server.Listener.Addr().String()))
}

func (s *Suite) TearDownSuite() {
	s.server.Close()
}

func (s *Suite) TestErrorWhenNotConfigured() {
	na := s.loadPlugin()
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "nodeattestor(gcp_iit): not configured")
}

func (s *Suite) TestUnexpectedStatus() {
	s.status = http.StatusBadGateway
	s.body = ""

	err := s.na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.Internal, "nodeattestor(gcp_iit): unable to retrieve valid identity token: unexpected status code: 502")
}

func (s *Suite) TestSuccessfulIdentityTokenProcessing() {
	require := s.Require()
	claims := gcp.IdentityToken{
		Google: gcp.Google{
			ComputeEngine: gcp.ComputeEngine{
				ProjectID:  "project-123",
				InstanceID: "instance-123",
			},
		},
	}
	s.body = signToken(s.T(), testkey.NewRSA2048(s.T()), "kid", claims)

	err := s.na.Attest(context.Background(), streamBuilder.ExpectAndBuild([]byte(s.body)))
	require.NoError(err)
}

func (s *Suite) TestConfigure() {
	require := s.Require()

	// malformed
	var err error
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure("malformed"),
	)
	require.Error(err)
}

func (s *Suite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), attestor, options...)
	return attestor
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
			url:               "http://127.0.0.1:70000",
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

func signToken(t *testing.T, key crypto.Signer, kid string, claims any) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: &jose.JSONWebKey{
			Key:   cryptosigner.Opaque(key),
			KeyID: kid,
		},
	}, nil)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}
