package httpchallenge_test

import (
	"context"
	"encoding/json"
	"testing"

	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
        "github.com/spiffe/go-spiffe/v2/spiffeid"
        agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_httpchallenge "github.com/spiffe/spire/pkg/common/plugin/httpchallenge"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/httpchallenge"
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
		//FIXME all the tofu checks
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
		// FIXME all the user port vs port config checks
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			plugin := loadPlugin(t, tt.hclConf)
			result, err := plugin.Attest(context.Background(), tt.payload, tt.challengeFn)
			require.Contains(t, err.Error(), tt.expErr)
			require.Nil(t, result)
		})
	}
}

func TestAttestSucceeds(t *testing.T) {
// FIXME Succeed tests
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
