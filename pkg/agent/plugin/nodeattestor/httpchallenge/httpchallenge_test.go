package httpchallenge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_httpchallenge "github.com/spiffe/spire/pkg/common/plugin/httpchallenge"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
)

var (
	streamBuilder = nodeattestortest.ServerStream("http_challenge")
)

func TestConfigureCommon(t *testing.T) {
	tests := []struct {
		name        string
		trustDomain string
		hclConf     string
		expErr      string
	}{
		{
			name:        "Configure fails if receives wrong HCL configuration",
			trustDomain: "example.org",
			hclConf:     "not HCL conf",
			expErr:      "rpc error: code = InvalidArgument desc = unable to decode configuration",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			plugin := newPlugin()

			resp, err := plugin.Configure(context.Background(), &configv1.ConfigureRequest{
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: tt.trustDomain,
				},
				HclConfiguration: tt.hclConf},
			)
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

func TestAidAttestationFailures(t *testing.T) {
	tests := []struct {
		name         string
		trustDomain  string
		config       string
		expErr       string
		serverStream nodeattestor.ServerStream
	}{
		{
			name:         "AidAttestation fails if server does not sends a challenge",
			trustDomain:  "example.org",
			config:       "",
			expErr:       "the error",
			serverStream: streamBuilder.FailAndBuild(errors.New("the error")),
		},
		{
			name:         "AidAttestation fails if agent cannot unmarshal server challenge",
			trustDomain:  "example.org",
			config:       "",
			expErr:       "rpc error: code = Internal desc = nodeattestor(http_challenge): unable to unmarshal challenge: invalid character 'o' in literal null (expecting 'u')",
			serverStream: streamBuilder.IgnoreThenChallenge([]byte("not-a-challenge")).Build(),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var err error
			p := loadAndConfigurePlugin(t, tt.trustDomain, tt.config)

			err = p.Attest(context.Background(), tt.serverStream)
			if tt.expErr != "" {
				require.Contains(t, err.Error(), tt.expErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAidAttestationSucceeds(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	defer l.Close()

	tests := []struct {
		name            string
		trustDomain     string
		config          string
		attestationData common_httpchallenge.AttestationData
		serverStream    func(attestationData *common_httpchallenge.AttestationData, challenge []byte, expectPayload []byte, challengeobj *common_httpchallenge.Challenge, port int) nodeattestor.ServerStream
	}{
		{
			name:        "Check for random port",
			trustDomain: "example.org",
			config:      "",
			attestationData: common_httpchallenge.AttestationData{
				HostName:  "spire-dev",
				AgentName: "default",
			},
			serverStream: func(attestationData *common_httpchallenge.AttestationData, challenge []byte, expectPayload []byte, challengeobj *common_httpchallenge.Challenge, port int) nodeattestor.ServerStream {
				return streamBuilder.
					Handle(func(challenge []byte) ([]byte, error) {
						attestationData := new(common_httpchallenge.AttestationData)
						if err := json.Unmarshal(challenge, attestationData); err != nil {
							return nil, err
						}
						if attestationData.Port == port {
							return nil, errors.New("random port failed")
						}
						return nil, nil
					}).Build()
			},
		},
		{
			name:        "Check for advertised port",
			trustDomain: "example.org",
			config:      fmt.Sprintf("advertised_port = %d", port),
			attestationData: common_httpchallenge.AttestationData{
				HostName:  "spire-dev",
				AgentName: "default",
			},
			serverStream: func(attestationData *common_httpchallenge.AttestationData, challenge []byte, expectPayload []byte, challengeobj *common_httpchallenge.Challenge, port int) nodeattestor.ServerStream {
				return streamBuilder.
					Handle(func(challenge []byte) ([]byte, error) {
						attestationData := new(common_httpchallenge.AttestationData)
						if err := json.Unmarshal(challenge, attestationData); err != nil {
							return nil, err
						}
						if attestationData.Port != port {
							return nil, errors.New("advertised port failed")
						}
						return nil, nil
					}).Build()
			},
		},
		{
			name:        "Test with defaults except port",
			trustDomain: "example.org",
			config:      "port=9999",
			attestationData: common_httpchallenge.AttestationData{
				HostName:  "localhost",
				AgentName: "default",
				Port:      9999,
			},
			serverStream: func(attestationData *common_httpchallenge.AttestationData, challenge []byte, expectPayload []byte, challengeobj *common_httpchallenge.Challenge, port int) nodeattestor.ServerStream {
				return streamBuilder.IgnoreThenChallenge(challenge).
					Handle(func(challengeResponse []byte) ([]byte, error) {
						err := common_httpchallenge.VerifyChallenge(context.Background(), http.DefaultClient, attestationData, challengeobj)
						return nil, err
					}).Build()
			},
		},
		{
			name:        "Full test with all the settings",
			trustDomain: "example.org",
			config:      "hostname=\"localhost\"\nagentname=\"test\"\nport=9999\nadvertised_port=9999",
			attestationData: common_httpchallenge.AttestationData{
				HostName:  "localhost",
				AgentName: "test",
				Port:      9999,
			},
			serverStream: func(attestationData *common_httpchallenge.AttestationData, challenge []byte, expectPayload []byte, challengeobj *common_httpchallenge.Challenge, port int) nodeattestor.ServerStream {
				return streamBuilder.ExpectThenChallenge(expectPayload, challenge).
					Handle(func(challengeResponse []byte) ([]byte, error) {
						err := common_httpchallenge.VerifyChallenge(context.Background(), http.DefaultClient, attestationData, challengeobj)
						return nil, err
					}).Build()
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var err error
			expectPayload, err := json.Marshal(&tt.attestationData)
			require.NoError(t, err)

			challengeobj, err := common_httpchallenge.GenerateChallenge("")
			require.NoError(t, err)

			challenge, err := json.Marshal(challengeobj)
			require.NoError(t, err)

			p := loadAndConfigurePlugin(t, tt.trustDomain, tt.config)

			err = p.Attest(context.Background(), tt.serverStream(&tt.attestationData, challenge, expectPayload, challengeobj, port))
			require.NoError(t, err)
		})
	}
}

func loadAndConfigurePlugin(t *testing.T, trustDomain string, config string) nodeattestor.NodeAttestor {
	return loadPlugin(t, plugintest.CoreConfig(catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString(trustDomain),
	}),
		plugintest.Configure(config))
}

func loadPlugin(t *testing.T, options ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(t, builtin(newPlugin()), na, options...)
	return na
}

func newPlugin() *Plugin {
	p := New()
	p.hooks.bindHost = "localhost"
	return p
}
