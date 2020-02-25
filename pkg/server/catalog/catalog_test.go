package catalog

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/hostservices/metricsservice"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	ctx := context.Background()

	// Create a custom list of BuiltIn plugins, it contains the minimal necessary plugins, and UpstreamCA with UpstreamAuthority
	builtIns = []catalog.Plugin{
		// Fake Datastore
		catalog.MakePlugin("fake_ds",
			datastore.PluginServer(fakedatastore.New())),
		// Fake key manager
		catalog.MakePlugin("fake_km",
			keymanager.PluginServer(&fakeKeyManager{})),
		// Fake UpstreamCA
		catalog.MakePlugin("fake_up",
			upstreamca.PluginServer(&fakeUpstreamCAPlugin{})),
		// Fake UpstreamAuthority
		catalog.MakePlugin("fake_up",
			upstreamauthority.PluginServer(&fakeUpstreamAuthorityPlugin{})),
	}

	// Create all fakes needed on Load method
	identityProvider := fakeidentityprovider.New()
	agentStore := fakeagentstore.New()

	metricsService := metricsservice.New(metricsservice.Config{
		Metrics: fakemetrics.New(),
	})
	log, _ := test.NewNullLogger()

	testCases := []struct {
		// Test case name
		name string
		// Function to create plugin configurations
		createHclConfig func() HCLPluginConfigMap
		// Ported UpstreamCAs
		ported map[string]bool
		// Expected error
		err string
		// Expect an upstream
		expectUpstream bool
	}{
		{
			name:            "no UpstreamCA or UpstreamAuthority config",
			createHclConfig: createDefaultConfig,
			expectUpstream:  false,
		},
		{
			name: "unported UpstreamCA",
			createHclConfig: func() HCLPluginConfigMap {
				c := createDefaultConfig()
				// Add fakeUpstreamCA to configuration
				c[upstreamca.Type] = map[string]HCLPluginConfig{"fake_up": {}}
				return c
			},
			expectUpstream: true,
		},
		{
			name: "ported UpstreamCA",
			createHclConfig: func() HCLPluginConfigMap {
				c := createDefaultConfig()
				// Add fakeUpstreamCA to configuration
				c[upstreamca.Type] = map[string]HCLPluginConfig{"fake_up": {}}
				return c
			},
			// Mark fake_up as ported plugin
			ported: map[string]bool{
				"fake_up": true,
			},
			expectUpstream: true,
		},
		{
			name: "contains UpstreamAuthority",
			createHclConfig: func() HCLPluginConfigMap {
				c := createDefaultConfig()
				// Add fakeUpstreamAuthority to configuration
				c[upstreamauthority.Type] = map[string]HCLPluginConfig{"fake_up": {}}
				return c
			},
			expectUpstream: true,
		},
		{
			name: "contains UpstreamAuthority and UpstreamCA",
			createHclConfig: func() HCLPluginConfigMap {
				c := createDefaultConfig()
				// Add UpstreamCA and UpstreamAuthority
				c[upstreamca.Type] = map[string]HCLPluginConfig{"fake_up": {}}
				c[upstreamauthority.Type] = map[string]HCLPluginConfig{"fake_up": {}}
				return c
			},
			err: "plugins UpstreamCA and UpstreamAuthority are mutually exclusive",
		},
		{
			name: "contains ported UpstreamCA and UpstreamAuthority",
			createHclConfig: func() HCLPluginConfigMap {
				c := createDefaultConfig()
				// Add UpstreamCA and UpstreamAuthority
				c[upstreamca.Type] = map[string]HCLPluginConfig{"fake_up": {}}
				c[upstreamauthority.Type] = map[string]HCLPluginConfig{"fake_up": {}}
				return c
			},
			// Add fake_up to ported plugins list
			ported: map[string]bool{"fake_up": true},
			err:    "\"fake_up\" cannot be configured as both an UpstreamCA and UpstreamAuthority",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			portedUpstreamCA = testCase.ported
			hclConfig := testCase.createHclConfig()

			repo, err := Load(ctx, Config{
				Log: log,
				GlobalConfig: catalog.GlobalConfig{
					TrustDomain: "domain.test",
				},
				PluginConfig:     hclConfig,
				IdentityProvider: identityProvider,
				AgentStore:       agentStore,
				MetricsService:   metricsService,
			})

			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}

			require.NoError(t, err)

			// Get upstream authority from catalog
			upstreamAuthority, ok := repo.Catalog.GetUpstreamAuthority()

			// Verify upstream is expected
			switch {
			case testCase.expectUpstream:
				require.True(t, ok)
				require.NotNil(t, upstreamAuthority)
			default:
				require.False(t, ok)
				require.Nil(t, upstreamAuthority)
			}
		})
	}
}

// createDefaultConfig create a HclPluginConfigMap with the minimal necessary plugins configuration
func createDefaultConfig() HCLPluginConfigMap {
	return HCLPluginConfigMap{
		datastore.Type:  map[string]HCLPluginConfig{"fake_ds": {}},
		keymanager.Type: map[string]HCLPluginConfig{"fake_km": {}},
	}
}

type fakeUpstreamAuthorityPlugin struct {
	upstreamauthority.UpstreamAuthorityServer
}

func (p *fakeUpstreamAuthorityPlugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (p fakeUpstreamAuthorityPlugin) MintX509CA(context.Context, *upstreamauthority.MintX509CARequest) (*upstreamauthority.MintX509CAResponse, error) {
	// Returning error with upstream name, it is done this way because wrapper is not exported, we are not able to get type from there
	return nil, errors.New("fakeUpstreamAuthority")
}

type fakeUpstreamCAPlugin struct{ upstreamca.UpstreamCAServer }

func (p *fakeUpstreamCAPlugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (p fakeUpstreamCAPlugin) SubmitCSR(context.Context, *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	// Returning error with upstream name, it is done this way because wrapper is not exported, we are not able to get type from there
	return &upstreamca.SubmitCSRResponse{}, errors.New("fakeUpstreamCA")
}

type fakeKeyManager struct{ keymanager.KeyManagerServer }

func (p *fakeKeyManager) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}
