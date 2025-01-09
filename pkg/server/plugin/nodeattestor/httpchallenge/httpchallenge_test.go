package httpchallenge_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_httpchallenge "github.com/spiffe/spire/pkg/common/plugin/httpchallenge"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/httpchallenge"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
)

func TestConfigure(t *testing.T) {
	tests := []struct {
		name     string
		hclConf  string
		coreConf *configv1.CoreConfiguration
		expErr   string
	}{
		{
			name:   "Configure fails if core config is not provided",
			expErr: "rpc error: code = InvalidArgument desc = server core configuration is required",
		},
		{
			name:     "Configure fails if trust domain is empty",
			expErr:   "rpc error: code = InvalidArgument desc = server core configuration must contain trust_domain",
			coreConf: &configv1.CoreConfiguration{},
		},
		{
			name:     "Configure fails if HCL config cannot be decoded",
			expErr:   "rpc error: code = InvalidArgument desc = unable to decode configuration",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf:  "not an HCL configuration",
		},
		{
			name:     "Configure fails if tofu and allow_non_root_ports",
			expErr:   "rpc error: code = InvalidArgument desc = you can not turn off trust on first use (TOFU) when non-root ports are allowed",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf:  "tofu = false\nallow_non_root_ports = true",
		},
		{
			name:     "Configure fails if tofu and required port >= 1024",
			expErr:   "rpc error: code = InvalidArgument desc = you can not turn off trust on first use (TOFU) when non-root ports are allowed",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf:  "tofu = false\nrequired_port = 1024",
		},
		{
			name:     "Configure fails if tofu and no other args",
			expErr:   "rpc error: code = InvalidArgument desc = you can not turn off trust on first use (TOFU) when non-root ports are allowed",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf:  "tofu = false",
		},
		{
			name:     "Configure fails if tofu and allow root ports is true",
			expErr:   "rpc error: code = InvalidArgument desc = you can not turn off trust on first use (TOFU) when non-root ports are allowed",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf:  "tofu = false\nallow_non_root_ports = true",
		},
		{
			name:     "allowed_dns_patterns cannot compile, report an error",
			expErr:   "rpc error: code = InvalidArgument desc = cannot compile allowed_dns_pattern: ",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf:  `allowed_dns_patterns = ["*"]`,
		},
		{
			name:     "first allowed_dns_patterns cannot compile, report an error",
			expErr:   "rpc error: code = InvalidArgument desc = cannot compile allowed_dns_pattern: ",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf: `allowed_dns_patterns = [
					"*",
					"gateway[.]example[.]com"
			  	  ]`,
		},
		{
			name:     "middle allowed_dns_patterns cannot compile, report an error",
			expErr:   "rpc error: code = InvalidArgument desc = cannot compile allowed_dns_pattern: ",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf: `allowed_dns_patterns = [
                                         "ps1[.]example[.]org",
                                         "*",
                                         "gateway[.]example[.]com"
                                   ]`,
		},
		{
			name:     "last allowed_dns_patterns cannot compile, report an error",
			expErr:   "rpc error: code = InvalidArgument desc = cannot compile allowed_dns_pattern: ",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf: `allowed_dns_patterns = [
                                         "gateway[.]example[.]com",
                                         "*"
                                   ]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := httpchallenge.New()
			resp, err := plugin.Configure(context.Background(), &configv1.ConfigureRequest{
				HclConfiguration:  tt.hclConf,
				CoreConfiguration: tt.coreConf,
			})
			if tt.expErr != "" {
				require.Error(t, err, "no error raised when error is expected")
				require.ErrorContains(t, err, tt.expErr)
				require.Nil(t, resp)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestAttestFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/spiffe/nodeattestor/http_challenge/default/challenge" {
			t.Errorf("Expected to request '/.well-known/spiffe/nodeattestor/http_challenge/default/challenge', got: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`123456789abcdefghijklmnopqrstuvwxyz`))
	}))
	defer server.Close()

	client := newClientWithLocalIntercept(server.URL)

	challengeFnNil := func(ctx context.Context, challenge []byte) ([]byte, error) {
		return nil, nil
	}

	tests := []struct {
		name        string
		hclConf     string
		expErr      string
		payload     []byte
		challengeFn func(ctx context.Context, challenge []byte) ([]byte, error)
		tofu        bool
	}{
		{
			name:        "Attest fails if payload doesnt exist",
			expErr:      "rpc error: code = InvalidArgument desc = payload cannot be empty",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload:     nil,
		},
		{
			name:        "Attest fails if payload cannot be unmarshalled",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(http_challenge): failed to unmarshal data: invalid character 'o' in literal null (expecting 'u')",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload:     []byte("not a payload"),
		},
		{
			name:        "Attest fails if hostname is blank",
			expErr:      "rpc error: code = PermissionDenied desc = nodeattestor(http_challenge): challenge verification failed: hostname must be set",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "",
				AgentName: "default",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails if agentname is blank",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(http_challenge): agent name is not valid",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails if hostname is localhost",
			expErr:      "rpc error: code = PermissionDenied desc = nodeattestor(http_challenge): you can not use localhost as a hostname",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "localhost",
				AgentName: "default",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails if port is 0",
			expErr:      "port is invalid",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      0,
			}),
		},
		{
			name:        "Attest fails if port is negative",
			expErr:      "port is invalid",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      -1,
			}),
		},
		{
			name:        "Attest fails if hostname has a slash",
			expErr:      "rpc error: code = PermissionDenied desc = nodeattestor(http_challenge): challenge verification failed: hostname can not contain a slash",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "fo/o",
				AgentName: "default",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails if hostname has a colon",
			expErr:      "rpc error: code = PermissionDenied desc = nodeattestor(http_challenge): challenge verification failed: hostname can not contain a colon",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo:1",
				AgentName: "default",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails if agentname has a dot",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(http_challenge): agent name is not valid",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "def.ault",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails if required port is different from given one",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(http_challenge): port 81 is not allowed to be used by this server",
			hclConf:     "required_port = 80",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      81,
			}),
		},
		{
			name:        "Attest fails if non root ports are disallowed and port is >= 1024",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(http_challenge): port 1024 is not allowed to be >= 1024",
			hclConf:     "allow_non_root_ports = false",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      1024,
			}),
		},
		{
			name:        "Attest fails if hostname is not valid by dns pattern",
			expErr:      "rpc error: code = PermissionDenied desc = nodeattestor(http_challenge): the requested hostname is not allowed to connect",
			hclConf:     `allowed_dns_patterns = ["p[0-9][.]example[.]com"]`,
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails if nonce does not match",
			expErr:      "rpc error: code = PermissionDenied desc = nodeattestor(http_challenge): challenge verification failed: expected nonce \"bad123456789abcdefghijklmnopqrstuvwxyz\" but got \"123456789abcdefghijklmnopqrstuvwxyz\"",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails when reattesting with tofu",
			expErr:      "rpc error: code = PermissionDenied desc = nodeattestor(http_challenge): attestation data has already been used to attest an agent",
			hclConf:     "",
			tofu:        false,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      80,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testNonce string
			if tt.tofu {
				testNonce = "bad123456789abcdefghijklmnopqrstuvwxyz"
			} else {
				testNonce = "123456789abcdefghijklmnopqrstuvwxyz"
			}
			plugin := loadPlugin(t, tt.hclConf, !tt.tofu, client, testNonce)
			result, err := plugin.Attest(context.Background(), tt.payload, tt.challengeFn)
			require.Contains(t, err.Error(), tt.expErr)
			require.Nil(t, result)
		})
	}
}

func TestAttestSucceeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/spiffe/nodeattestor/http_challenge/default/challenge" {
			t.Errorf("Expected to request '/.well-known/spiffe/nodeattestor/http_challenge/default/challenge', got: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`123456789abcdefghijklmnopqrstuvwxyz`))
	}))
	defer server.Close()

	client := newClientWithLocalIntercept(server.URL)

	challengeFnNil := func(ctx context.Context, challenge []byte) ([]byte, error) {
		return nil, nil
	}

	tests := []struct {
		name              string
		hclConf           string
		payload           []byte
		challengeFn       func(ctx context.Context, challenge []byte) ([]byte, error)
		expectedAgentID   string
		expectedSelectors []*common.Selector
		tofu              bool
	}{
		{
			name:        "Attest succeeds for defaults",
			hclConf:     "",
			tofu:        true,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      80,
			}),
			expectedAgentID: "spiffe://example.org/spire/agent/http_challenge/foo",
			expectedSelectors: []*common.Selector{
				{
					Type:  "http_challenge",
					Value: "hostname:foo",
				},
			},
		},
		{
			name:        "Attest succeeds for reattest without tofu",
			hclConf:     "tofu = false\nallow_non_root_ports = false",
			tofu:        false,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      80,
			}),
			expectedAgentID: "spiffe://example.org/spire/agent/http_challenge/foo",
			expectedSelectors: []*common.Selector{
				{
					Type:  "http_challenge",
					Value: "hostname:foo",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testNonce := "123456789abcdefghijklmnopqrstuvwxyz"
			plugin := loadPlugin(t, tt.hclConf, !tt.tofu, client, testNonce)
			result, err := plugin.Attest(context.Background(), tt.payload, tt.challengeFn)
			require.NoError(t, err)
			require.NotNil(t, result)

			require.Equal(t, tt.expectedAgentID, result.AgentID)
			requireSelectorsMatch(t, tt.expectedSelectors, result.Selectors)
		})
	}
}

func loadPlugin(t *testing.T, config string, testTOFU bool, client *http.Client, testNonce string) nodeattestor.NodeAttestor {
	v1 := new(nodeattestor.V1)
	agentStore := fakeagentstore.New()
	var configureErr error
	if testTOFU {
		agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
			AgentId: "spiffe://example.org/spire/agent/http_challenge/foo",
		})
	}
	opts := []plugintest.Option{
		plugintest.Configure(config),
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	}
	plugintest.Load(t, httpchallenge.BuiltInTesting(client, testNonce), v1, opts...)
	return v1
}

func marshalPayload(t *testing.T, attReq *common_httpchallenge.AttestationData) []byte {
	attReqBytes, err := json.Marshal(attReq)
	require.NoError(t, err)
	return attReqBytes
}

func requireSelectorsMatch(t *testing.T, expected []*common.Selector, actual []*common.Selector) {
	require.Equal(t, len(expected), len(actual))
	for idx, expSel := range expected {
		require.Equal(t, expSel.Type, actual[idx].Type)
		require.Equal(t, expSel.Value, actual[idx].Value)
	}
}

func newClientWithLocalIntercept(url string) *http.Client {
	u, _ := neturl.Parse(url)
	_, port, _ := net.SplitHostPort(u.Host)
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				defaultDialContext := http.DefaultTransport.(*http.Transport).DialContext
				if addr == "foo:80" {
					addr = fmt.Sprintf("127.0.0.1:%s", port)
				}
				return defaultDialContext(ctx, network, addr)
			},
		},
	}
}
