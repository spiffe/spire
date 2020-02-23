package catalog

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/hostservices/metricsservice"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tempDir, err := ioutil.TempDir("", "database")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	hclConfig := createDefaultConfig(t, tempDir)

	builtIn = append(builtIn, catalog.MakePlugin("testUpstream",
		upstreamca.PluginServer(fakeUpstreamCAPlugin{}),
	), catalog.MakePlugin("testUpstream",
		upstreamauthority.PluginServer(fakeUpstreamAuthorityPlugin{}),
	))

	identityProvider := fakeidentityprovider.New()
	agentStore := fakeagentstore.New()

	metricsService := metricsservice.New(metricsservice.Config{
		Metrics: fakemetrics.New(),
	})
	log, _ := test.NewNullLogger()

	testCases := []struct {
		name            string
		createHclConfig func() HCLPluginConfigMap
		ported          map[string]bool
		err             string
		verifyRepo      func(*testing.T, *Repository)
	}{
		{
			name: "default config",
			createHclConfig: func() HCLPluginConfigMap {
				return hclConfig
			},
			verifyRepo: func(t *testing.T, repository *Repository) {
				upstream, ok := repository.Catalog.GetUpstreamAuthority()
				require.False(t, ok)
				require.Nil(t, upstream)
			},
		},
		{
			name: "contains unported UpstreamCA",
			createHclConfig: func() HCLPluginConfigMap {
				c := hclConfig
				c[upstreamca.Type] = map[string]HCLPluginConfig{"testUpstream": {}}
				return c
			},
			verifyRepo: func(t *testing.T, repository *Repository) {
				upstream, ok := repository.Catalog.GetUpstreamAuthority()
				require.True(t, ok)
				require.NotNil(t, upstream)

				_, err := upstream.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{})
				require.Error(t, err, "fakeUpstreamCA")
			},
		},
		{
			name: "contains ported UpstreamCA",
			createHclConfig: func() HCLPluginConfigMap {
				c := hclConfig
				c[upstreamca.Type] = map[string]HCLPluginConfig{"testUpstream": {}}
				return c
			},
			ported: map[string]bool{
				"testUpstream": true,
			},
			verifyRepo: func(t *testing.T, repository *Repository) {
				upstream, ok := repository.Catalog.GetUpstreamAuthority()
				require.True(t, ok)
				require.NotNil(t, upstream)

				_, err := upstream.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{})
				require.Error(t, err, "fakeUpstreamAuthority")
			},
		},
		{
			name: "contains UpstreamAuthority",
			createHclConfig: func() HCLPluginConfigMap {
				c := hclConfig
				c[upstreamauthority.Type] = map[string]HCLPluginConfig{"testUpstream": {}}
				return c
			},
			verifyRepo: func(t *testing.T, repository *Repository) {
				upstream, ok := repository.Catalog.GetUpstreamAuthority()
				require.True(t, ok)
				require.NotNil(t, upstream)

				_, err := upstream.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{})
				require.Error(t, err, "fakeUpstreamAuthority")
			},
		},
		{
			name: "contains UpstreamAuthority and UpstreamCA",
			createHclConfig: func() HCLPluginConfigMap {
				c := hclConfig
				c[upstreamca.Type] = map[string]HCLPluginConfig{"testUpstream": {}}
				c[upstreamauthority.Type] = map[string]HCLPluginConfig{"testUpstream": {}}
				return c
			},
			err: "only one UpstreamCA or UpstreamAuthority is allowed. Please remove one of them",
			verifyRepo: func(t *testing.T, repository *Repository) {
				upstream, ok := repository.Catalog.GetUpstreamAuthority()
				require.True(t, ok)
				require.NotNil(t, upstream)

				_, err := upstream.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{})
				require.Error(t, err, "fakeUpstreamAuthority")
			},
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
				require.Error(t, err, testCase.err)
				return
			}

			require.NoError(t, err)
			testCase.verifyRepo(t, repo)
		})
	}
}

func createDefaultConfig(t *testing.T, sqlPath string) HCLPluginConfigMap {
	config := fmt.Sprintf(`
 	DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "%s/testit"

        }
    }
    NodeAttestor "join_token" {
        plugin_data {
        }
    }

    NodeResolver "noop" {
        plugin_data {}
    }

    KeyManager "memory" {
        plugin_data = {}
    }
`, sqlPath)
	var hclConfig HCLPluginConfigMap
	err := hcl.Decode(&hclConfig, config)
	require.NoError(t, err)

	return hclConfig
}

type fakeUpstreamAuthorityPlugin struct {
}

func (p fakeUpstreamAuthorityPlugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (p fakeUpstreamAuthorityPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p fakeUpstreamAuthorityPlugin) MintX509CA(context.Context, *upstreamauthority.MintX509CARequest) (*upstreamauthority.MintX509CAResponse, error) {
	return nil, errors.New("fakeUpstreamAuthority")
}

func (p fakeUpstreamAuthorityPlugin) PublishJWTKey(context.Context, *upstreamauthority.PublishJWTKeyRequest) (*upstreamauthority.PublishJWTKeyResponse, error) {
	return &upstreamauthority.PublishJWTKeyResponse{}, nil
}

func (p fakeUpstreamAuthorityPlugin) PublishX509CA(context.Context, *upstreamauthority.PublishX509CARequest) (*upstreamauthority.PublishX509CAResponse, error) {
	return &upstreamauthority.PublishX509CAResponse{}, nil
}

type fakeUpstreamCAPlugin struct {
}

func (p fakeUpstreamCAPlugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (p fakeUpstreamCAPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p fakeUpstreamCAPlugin) SubmitCSR(context.Context, *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	return &upstreamca.SubmitCSRResponse{}, errors.New("fakeUpstreamCA")
}
