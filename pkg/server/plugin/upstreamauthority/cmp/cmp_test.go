package cmp

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name          string
		config        string
		expectCode    codes.Code
		expectMessage string
	}{
		{
			name: "valid config",
			config: `
				hostname = "cmp.example.org"
			`,
			expectCode: codes.OK,
		},
		{
			name: "missing hostname",
			config: `
				client_cert_path = "/tmp/client-cert.pem"
				client_cert_key_path = "/tmp/client-key.pem"
			`,
			expectCode:    codes.InvalidArgument,
			expectMessage: "hostname is required",
		},
		{
			name: "malformed config",
			config: `
				this is not valid hcl
			`,
			expectCode:    codes.InvalidArgument,
			expectMessage: "plugin configuration is malformed",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			var err error

			plugintest.Load(t, builtin(p), nil,
				plugintest.CaptureConfigureError(&err),
				plugintest.Configure(tt.config),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
			)

			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMessage)
			if tt.expectCode == codes.OK {
				cfg, err := p.getConfig()
				require.NoError(t, err)
				require.NotNil(t, cfg)
				require.Equal(t, "cmp.example.org", cfg.Hostname)
			}
		})
	}
}

func TestMintX509CAAndSubscribe(t *testing.T) {
	for _, tt := range []struct {
		name          string
		configure     bool
		expectCode    codes.Code
		expectMessage string
	}{
		{
			name:          "configured",
			configure:     true,
			expectCode:    codes.Unimplemented,
			expectMessage: "CMP upstreamauthority is not implemented",
		},
		{
			name:          "not configured",
			configure:     false,
			expectCode:    codes.FailedPrecondition,
			expectMessage: "cmp upstreamauthority is not configured",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			if tt.configure {
				p.setConfig(&Config{Hostname: "cmp.example.org"})
			}

			err := p.MintX509CAAndSubscribe(&upstreamauthorityv1.MintX509CARequest{}, nil)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMessage)
		})
	}
}

func TestUnsupportedRPCs(t *testing.T) {
	p := New()

	t.Run("PublishJWTKeyAndSubscribe", func(t *testing.T) {
		err := p.PublishJWTKeyAndSubscribe(nil, nil)
		spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "publishing JWT keys is not supported by the CMP upstreamauthority plugin")
	})

	t.Run("SubscribeToLocalBundle", func(t *testing.T) {
		err := p.SubscribeToLocalBundle(nil, nil)
		spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "fetching upstream trust bundle is unsupported")
	})
}
