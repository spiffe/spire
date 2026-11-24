package pluginconf_test

import (
	"testing"

	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/plugindecode"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	for _, tt := range []struct {
		name       string
		req        *configv1.ConfigureRequest
		wantText   string
		wantFormat catalog.ConfigFormat
		wantErr    string
	}{
		{
			name:       "older SPIRE sends only HCL",
			req:        &configv1.ConfigureRequest{HclConfiguration: "a = 1"}, //nolint:staticcheck // legacy field
			wantText:   "a = 1",
			wantFormat: catalog.ConfigFormatHCL,
		},
		{
			name:       "unspecified format means HCL",
			req:        &configv1.ConfigureRequest{Configuration: "a = 1"},
			wantText:   "a = 1",
			wantFormat: catalog.ConfigFormatHCL,
		},
		{
			name: "YAML",
			req: &configv1.ConfigureRequest{
				HclConfiguration: "legacy", //nolint:staticcheck // legacy field
				Configuration:    "a: 1",
				ConfigFormat:     configv1.ConfigFormat_CONFIG_FORMAT_YAML,
			},
			wantText:   "a: 1",
			wantFormat: catalog.ConfigFormatYAML,
		},
		{
			name: "empty YAML ignores the legacy field",
			req: &configv1.ConfigureRequest{
				HclConfiguration: "legacy", //nolint:staticcheck // legacy field
				ConfigFormat:     configv1.ConfigFormat_CONFIG_FORMAT_YAML,
			},
			wantText:   "",
			wantFormat: catalog.ConfigFormatYAML,
		},
		{
			name:    "unsupported format",
			req:     &configv1.ConfigureRequest{Configuration: "a", ConfigFormat: 42},
			wantErr: "unsupported configuration format 42",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			text, format, err := pluginconf.Config(tt.req)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantText, text)
			require.Equal(t, tt.wantFormat, format)
		})
	}
}

func TestBuildPassesFormat(t *testing.T) {
	type config struct {
		A int `hcl:"a" yaml:"a"`
	}
	build := func(_ catalog.CoreConfig, text string, format catalog.ConfigFormat, s *pluginconf.Status) *config {
		c := new(config)
		if err := plugindecode.DecodeConfig(text, format, c); err != nil {
			s.ReportError(err.Error())
		}
		return c
	}

	c, _, err := pluginconf.Build(&configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		Configuration:     "a: 1",
		ConfigFormat:      configv1.ConfigFormat_CONFIG_FORMAT_YAML,
	}, build)
	require.NoError(t, err)
	require.Equal(t, 1, c.A)

	_, _, err = pluginconf.Build(&configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		ConfigFormat:      42,
	}, build)
	require.ErrorContains(t, err, "unsupported configuration format 42")
}
