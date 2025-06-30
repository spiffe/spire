package k8sconfigmap

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		configureRequest *configv1.ConfigureRequest
		newClientErr     error
		hclConfig        string
		expectCode       codes.Code
		expectMsg        string
		expectCfg        *Config
	}{
		{
			name: "success",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						format = "spiffe"
						namespace = "spire"
						configmap_name = "spire-bundle"
						configmap_key = "bundle.json"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"test-cluster": {
						Format:         "spiffe",
						Namespace:      "spire",
						ConfigMapName:  "spire-bundle",
						ConfigMapKey:   "bundle.json",
						KubeConfigPath: "/path/to/kubeconfig",
					},
				},
			},
		},
		{
			name: "no namespace",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						format = "spiffe"
						configmap_name = "spire-bundle"
						configmap_key = "bundle.json"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing namespace in cluster \"test-cluster\"",
		},
		{
			name: "no configmap name",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						format = "spiffe"
						namespace = "spire"
						configmap_key = "bundle.json"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing configmap name in cluster \"test-cluster\"",
		},
		{
			name: "no configmap key",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						format = "spiffe"
						namespace = "spire"
						configmap_name = "spire-bundle"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing configmap key in cluster \"test-cluster\"",
		},
		{
			name: "no bundle format",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						namespace = "spire"
						configmap_name = "spire-bundle"
						configmap_key = "bundle.json"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing bundle format in cluster \"test-cluster\"",
		},
		{
			name: "bundle format not supported",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						format = "unsupported"
						namespace = "spire"
						configmap_name = "spire-bundle"
						configmap_key = "bundle.json"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse bundle format from cluster \"test-cluster\": unknown bundle format: \"unsupported\"",
		},
		{
			name: "client error",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						format = "spiffe"
						namespace = "spire"
						configmap_name = "spire-bundle"
						configmap_key = "bundle.json"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode:   codes.Internal,
			expectMsg:    "failed to create Kubernetes client for cluster \"test-cluster\"",
			newClientErr: errors.New("client creation error"),
		},
		{
			name:       "invalid config",
			hclConfig:  "invalid config",
			expectCode: codes.InvalidArgument,
			expectMsg:  "unable to decode configuration",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.Configure(tt.hclConfig),
			}

			newClient := func(kubeconfigPath string) (kubernetesClient, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return &fakeClient{}, nil
			}
			p := newPlugin(newClient)

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)

			if tt.expectMsg != "" {
				require.Nil(t, p.config)
				return
			}

			// Check that the plugin has the expected configuration.
			for i, cluster := range p.config.Clusters {
				require.Equal(t, tt.expectCfg.Clusters[i].Format, cluster.Format)
				require.Equal(t, tt.expectCfg.Clusters[i].Namespace, cluster.Namespace)
				require.Equal(t, tt.expectCfg.Clusters[i].ConfigMapName, cluster.ConfigMapName)
				require.Equal(t, tt.expectCfg.Clusters[i].ConfigMapKey, cluster.ConfigMapKey)
				require.Equal(t, tt.expectCfg.Clusters[i].KubeConfigPath, cluster.KubeConfigPath)
			}
		})
	}
}

func TestPublishBundle(t *testing.T) {
	testBundle := getTestBundle(t)

	for _, tt := range []struct {
		name string

		hclConfig         string
		newClientErr      error
		expectCode        codes.Code
		expectMsg         string
		bundle            *types.Bundle
		applyConfigMapErr error
	}{
		{
			name:   "success",
			bundle: testBundle,
			hclConfig: `
				clusters = {
					"test-cluster" = {
						format = "spiffe"
						namespace = "spire"
						configmap_name = "spire-bundle"
						configmap_key = "bundle.json"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
		},
		{
			name:   "apply error",
			bundle: testBundle,
			hclConfig: `
				clusters = {
					"test-cluster" = {
						format = "spiffe"
						namespace = "spire"
						configmap_name = "spire-bundle"
						configmap_key = "bundle.json"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			applyConfigMapErr: errors.New("apply error"),
			expectCode:        codes.Internal,
			expectMsg:         "failed to apply ConfigMap for cluster \"test-cluster\": apply error",
		},
		{
			name: "missing bundle",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						format = "spiffe"
						namespace = "spire"
						configmap_name = "spire-bundle"
						configmap_key = "bundle.json"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing bundle in request",
		},
		{
			name:       "not configured",
			expectCode: codes.FailedPrecondition,
			expectMsg:  "not configured",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			var options []plugintest.Option
			if tt.hclConfig != "" {
				options = []plugintest.Option{
					plugintest.CaptureConfigureError(&err),
					plugintest.CoreConfig(catalog.CoreConfig{
						TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
					}),
					plugintest.Configure(tt.hclConfig),
				}
			}
			// Set up test client
			client := &fakeClient{
				t:                 t,
				applyConfigMapErr: tt.applyConfigMapErr,
			}

			newClient := func(kubeconfigPath string) (kubernetesClient, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return client, nil
			}
			p := newPlugin(newClient)

			plugintest.Load(t, builtin(p), nil, options...)
			require.NoError(t, err)

			resp, err := p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{
				Bundle: tt.bundle,
			})

			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestPublishMultiple(t *testing.T) {
	hclConfig := `
		clusters = {
			"test-cluster" = {
				format = "spiffe"
				namespace = "spire"
				configmap_name = "spire-bundle"
				configmap_key = "bundle.json"
				kubeconfig_path = "/path/to/kubeconfig"
			}
		}`

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(hclConfig),
	}

	client := &fakeClient{t: t}
	newClientFunc := func(kubeconfigPath string) (kubernetesClient, error) {
		return client, nil
	}

	p := newPlugin(newClientFunc)
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	// Test multiple update operations, and check that only a call to update ConfigMap is
	// done when there is a modified bundle that was not successfully published before.

	// Have an initial bundle with SequenceNumber = 1.
	bundle := getTestBundle(t)
	bundle.SequenceNumber = 1

	// Reset the update counter.
	client.updateCount = 0
	resp, err := p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, client.updateCount)

	// Call PublishBundle with the same bundle.
	resp, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the updateCount counter should be still 1.
	require.Equal(t, 1, client.updateCount)

	// Have a new bundle and call PublishBundle.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 2
	resp, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// PublishBundle was called with a different bundle, updateCount should
	// be incremented to be 2.
	require.Equal(t, 2, client.updateCount)
}

func TestBuiltIn(t *testing.T) {
	p := BuiltIn()
	require.NotNil(t, p)
	require.Equal(t, pluginName, p.Name)
}

func TestValidate(t *testing.T) {
	p := New()
	require.NotNil(t, p)

	for _, tt := range []struct {
		name        string
		req         *configv1.ValidateRequest
		expectCode  codes.Code
		expectMsg   string
		expectNotes []string
	}{
		{
			name: "valid configuration",
			req: &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: "example.org",
				},
				HclConfiguration: `
					clusters = {
						"test-cluster" = {
							format = "spiffe"
							namespace = "spire"
							configmap_name = "spire-bundle"
							configmap_key = "bundle.json"
							kubeconfig_path = "/path/to/kubeconfig"
						}
					}`,
			},
		},
		{
			name: "note about no clusters",
			req: &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: "example.org",
				},
			},
			expectNotes: []string{"No clusters configured, bundle will not be published"},
		},

		{
			name: "missing trust domain",
			req: &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "server core configuration must contain trust_domain",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Validate(t.Context(), tt.req)
			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			if tt.expectNotes != nil {
				require.NotNil(t, resp)
				require.Equal(t, tt.expectNotes, resp.Notes)
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

type fakeClient struct {
	t *testing.T

	applyConfigMapErr error
	updateCount       int
}

func (c *fakeClient) ApplyConfigMap(ctx context.Context, cluster *Cluster, data []byte) error {
	if c.applyConfigMapErr != nil {
		return c.applyConfigMapErr
	}

	c.updateCount++
	return nil
}

func getTestBundle(t *testing.T) *types.Bundle {
	cert, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	keyPkix, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	return &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: cert.Raw}},
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID",
				PublicKey: keyPkix,
			},
		},
		RefreshHint:    1440,
		SequenceNumber: 100,
	}
}
