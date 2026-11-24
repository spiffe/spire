package catalog

import (
	"context"
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func TestConfigurerV1Requests(t *testing.T) {
	coreConfig := CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}
	for _, tt := range []struct {
		format ConfigFormat
		data   string
		legacy string
		proto  configv1.ConfigFormat
	}{
		{ConfigFormatHCL, "data", "data", configv1.ConfigFormat_CONFIG_FORMAT_HCL},
		{ConfigFormatYAML, `{"data": 1}`, yamlNotSupportedHCL, configv1.ConfigFormat_CONFIG_FORMAT_YAML},
		{ConfigFormatYAML, "{}\n", "", configv1.ConfigFormat_CONFIG_FORMAT_YAML},
	} {
		client := &fakeConfigClient{}
		configurer := &configurerV1{}
		configurer.ConfigClient = client

		require.NoError(t, configurer.Configure(context.Background(), coreConfig, tt.data, tt.format))
		_, err := configurer.Validate(context.Background(), coreConfig, tt.data, tt.format)
		require.NoError(t, err)

		core := &configv1.CoreConfiguration{TrustDomain: "example.org"}
		require.True(t, proto.Equal(&configv1.ConfigureRequest{
			CoreConfiguration: core,
			HclConfiguration:  tt.legacy, //nolint:staticcheck // legacy field is still sent
			Configuration:     tt.data,
			ConfigFormat:      tt.proto,
		}, client.configureReq), "%v", client.configureReq)
		require.True(t, proto.Equal(&configv1.ValidateRequest{
			CoreConfiguration: core,
			HclConfiguration:  tt.legacy, //nolint:staticcheck // legacy field is still sent
			Configuration:     tt.data,
			ConfigFormat:      tt.proto,
		}, client.validateReq), "%v", client.validateReq)
	}
}

type fakeConfigClient struct {
	configureReq *configv1.ConfigureRequest
	validateReq  *configv1.ValidateRequest
}

func (c *fakeConfigClient) Configure(_ context.Context, req *configv1.ConfigureRequest, _ ...grpc.CallOption) (*configv1.ConfigureResponse, error) {
	c.configureReq = req
	return &configv1.ConfigureResponse{}, nil
}

func (c *fakeConfigClient) Validate(_ context.Context, req *configv1.ValidateRequest, _ ...grpc.CallOption) (*configv1.ValidateResponse, error) {
	c.validateReq = req
	return &configv1.ValidateResponse{}, nil
}

func TestYAMLNotSupportedHCL(t *testing.T) {
	var out map[string]any
	require.ErrorContains(t, hcl.Decode(&out, yamlNotSupportedHCL), "YAML configuration requires a plugin built with a SPIRE plugin SDK that supports it")
}
