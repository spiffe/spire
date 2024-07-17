package httpchallenge_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/http"
	"net/url"
	"net"
	"strings"
	"testing"
	"fmt"

	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
        "github.com/spiffe/go-spiffe/v2/spiffeid"
        agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_httpchallenge "github.com/spiffe/spire/pkg/common/plugin/httpchallenge"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/httpchallenge"
        "github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/proto/spire/common"
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
			expErr: "rpc error: code = InvalidArgument desc = core configuration is required",
		},
		{
			name:     "Configure fails if trust domain is empty",
			expErr:   "rpc error: code = InvalidArgument desc = trust_domain is required",
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
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			plugin := httpchallenge.New()
			resp, err := plugin.Configure(context.Background(), &configv1.ConfigureRequest{
				HclConfiguration:  tt.hclConf,
				CoreConfiguration: tt.coreConf,
			})
			if tt.expErr != "" {
				require.Contains(t, err.Error(), tt.expErr)
				require.Nil(t, resp)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestAttestFailiures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	    if r.URL.Path != "/.well-known/spiffe/nodeattestor/http_challenge/default/challenge" {
	        t.Errorf("Expected to request '/.well-known/spiffe/nodeattestor/http_challenge/default/challenge', got: %s", r.URL.Path)
	    }
	    w.WriteHeader(http.StatusOK)
	    w.Write([]byte(`MTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc=`))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	oldDialContext := http.DefaultTransport.(*http.Transport).DialContext
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "foo:80" {
			addr = fmt.Sprintf("127.0.0.1:%s", port)
		}
		return oldDialContext(ctx, network, addr)
	}
	http.DefaultTransport.(*http.Transport).DialContext = dialContext

	challengeFnNil := func(ctx context.Context, challenge []byte) ([]byte, error) {
		return nil, nil
	}

	tests := []struct {
		name        string
		hclConf     string
		expErr      string
		payload     []byte
		challengeFn func(ctx context.Context, challenge []byte) ([]byte, error)
	}{
		{
			name:        "Attest fails if payload doesnt exist",
			expErr:      "rpc error: code = InvalidArgument desc = payload cannot be empty",
			hclConf:     "",
			challengeFn: challengeFnNil,
			payload:     nil,
		},
		{
			name:        "Attest fails if payload cannot be unmarshalled",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(http_challenge): failed to unmarshal data: invalid character 'o' in literal null (expecting 'u')",
			hclConf:     "",
			challengeFn: challengeFnNil,
			payload:     []byte("not a payload"),
		},
		{
			name:        "Attest fails if hostname is blank",
			expErr:      "rpc error: code = PermissionDenied desc = nodeattestor(http_challenge): challenge verification failed: hostname must be set",
			hclConf:     "",
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
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails if port is 0",
			expErr:      "port is invalid",
			hclConf:     "",
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
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      80,
			}),
		},
		{
			name:        "Attest fails if nonce does not match",
			expErr:      "rpc error: code = PermissionDenied desc = nodeattestor(http_challenge): challenge verification failed: expected nonce \"YmFkMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3Q=\"",
			hclConf:     "",
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_httpchallenge.AttestationData{
				HostName:  "foo",
				AgentName: "default",
				Port:      80,
			}),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			common_httpchallenge.DefaultRandReader = strings.NewReader("bad123456789abcdefghijklmnopqrstuvwxyz")
			plugin := loadPlugin(t, tt.hclConf)
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
	    w.Write([]byte(`MTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc=`))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	oldDialContext := http.DefaultTransport.(*http.Transport).DialContext
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "foo:80" {
			addr = fmt.Sprintf("127.0.0.1:%s", port)
		}
		return oldDialContext(ctx, network, addr)
	}
	http.DefaultTransport.(*http.Transport).DialContext = dialContext

	challengeFnNil := func(ctx context.Context, challenge []byte) ([]byte, error) {
		return nil, nil
	}

	tests := []struct {
		name        string
		hclConf     string
		payload     []byte
		challengeFn func(ctx context.Context, challenge []byte) ([]byte, error)
		expectedAgentID   string
		expectedSelectors []*common.Selector
	}{
		{
			name:        "Attest succeedsfails for defaults",
			hclConf:     "",
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			common_httpchallenge.DefaultRandReader = strings.NewReader("123456789abcdefghijklmnopqrstuvwxyz")
			plugin := loadPlugin(t, tt.hclConf)
			result, err := plugin.Attest(context.Background(), tt.payload, tt.challengeFn)
			require.NoError(t, err)
			require.NotNil(t, result)

			require.Equal(t, tt.expectedAgentID, result.AgentID)
			requireSelectorsMatch(t, tt.expectedSelectors, result.Selectors)
		})
	}
}

func loadPlugin(t *testing.T, config string) nodeattestor.NodeAttestor {
	v1 := new(nodeattestor.V1)
	agentStore := fakeagentstore.New()
	agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
	})
	var configureErr error
	opts := []plugintest.Option{
		plugintest.Configure(config),
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	}
	plugintest.Load(t, httpchallenge.BuiltIn(), v1, opts...)
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
