package k8sclustertrustbundle

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		newClientErr error
		hclConfig    string
		expectCode   codes.Code
		expectMsg    string
		expectCfg    *Config
	}{
		{
			name: "success",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						cluster_trust_bundle_name = "spire-bundle"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"test-cluster": {
						ClusterTrustBundleName: "spire-bundle",
						KubeConfigPath:         "/path/to/kubeconfig",
					},
				},
			},
		},
		{
			name: "success with signer name",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						cluster_trust_bundle_name = "example.org:spire:bundle"
						signer_name = "example.org/spire"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"test-cluster": {
						ClusterTrustBundleName: "example.org:spire:bundle",
						SignerName:             "example.org/spire",
						KubeConfigPath:         "/path/to/kubeconfig",
					},
				},
			},
		},
		{
			name: "no cluster trust bundle name",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing cluster trust bundle name in cluster \"test-cluster\"",
		},
		{
			name: "name without signer name prefix",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						cluster_trust_bundle_name = "spire-bundle"
						signer_name = "example.org/spire"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "cluster trust bundle name \"spire-bundle\" in cluster \"test-cluster\" must have the prefix \"example.org:spire:\" when signer_name is set",
		},
		{
			name: "name with signer name prefix missing the trailing colon",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						cluster_trust_bundle_name = "example.org:spirebundle"
						signer_name = "example.org/spire"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "must have the prefix \"example.org:spire:\" when signer_name is set",
		},
		{
			name: "name with colon without signer name",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						cluster_trust_bundle_name = "example.org:spire:bundle"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "cluster trust bundle name \"example.org:spire:bundle\" in cluster \"test-cluster\" must not contain \":\" when signer_name is not set",
		},
		{
			name: "client error",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						cluster_trust_bundle_name = "spire-bundle"
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
				require.Equal(t, tt.expectCfg.Clusters[i].ClusterTrustBundleName, cluster.ClusterTrustBundleName)
				require.Equal(t, tt.expectCfg.Clusters[i].SignerName, cluster.SignerName)
				require.Equal(t, tt.expectCfg.Clusters[i].KubeConfigPath, cluster.KubeConfigPath)
			}
		})
	}
}

func TestPublishBundle(t *testing.T) {
	testBundle := getTestBundle(t)
	noX509Bundle := getTestBundle(t)
	noX509Bundle.X509Authorities = nil

	for _, tt := range []struct {
		name string

		hclConfig  string
		expectCode codes.Code
		expectMsg  string
		bundle     *types.Bundle
		applyErr   error
	}{
		{
			name:   "success",
			bundle: testBundle,
			hclConfig: `
				clusters = {
					"test-cluster" = {
						cluster_trust_bundle_name = "spire-bundle"
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
						cluster_trust_bundle_name = "spire-bundle"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			applyErr:   errors.New("apply error"),
			expectCode: codes.Internal,
			expectMsg:  "failed to apply ClusterTrustBundle for cluster \"test-cluster\": apply error",
		},
		{
			name:   "no X.509 authorities",
			bundle: noX509Bundle,
			hclConfig: `
				clusters = {
					"test-cluster" = {
						cluster_trust_bundle_name = "spire-bundle"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "bundle has no X.509 authorities",
		},
		{
			name: "missing bundle",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						cluster_trust_bundle_name = "spire-bundle"
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
			client := &fakeClient{
				applyErr: tt.applyErr,
			}

			newClient := func(kubeconfigPath string) (kubernetesClient, error) {
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
				require.Zero(t, client.updateCount)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, 1, client.updateCount)
		})
	}
}

func TestPublishMultiple(t *testing.T) {
	hclConfig := `
		clusters = {
			"test-cluster" = {
				cluster_trust_bundle_name = "spire-bundle"
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

	client := &fakeClient{}
	newClientFunc := func(kubeconfigPath string) (kubernetesClient, error) {
		return client, nil
	}

	p := newPlugin(newClientFunc)
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	// Test multiple update operations, and check that only a call to apply the
	// ClusterTrustBundle is done when there is a modified bundle that was not
	// successfully published before.

	// Have an initial bundle with SequenceNumber = 1.
	bundle := getTestBundle(t)
	bundle.SequenceNumber = 1

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

func TestPublishMultipleClusters(t *testing.T) {
	hclConfig := `
		clusters = {
			"test-cluster" = {
				cluster_trust_bundle_name = "spire-bundle"
				kubeconfig_path = "/path/to/kubeconfig"
			}
			"test-cluster-2" = {
				cluster_trust_bundle_name = "example.org:spire:bundle"
				signer_name = "example.org/spire"
				kubeconfig_path = "/path/to/kubeconfig-2"
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

	clients := map[string]*fakeClient{
		"/path/to/kubeconfig":   {},
		"/path/to/kubeconfig-2": {applyErr: errors.New("apply error")},
	}
	newClientFunc := func(kubeconfigPath string) (kubernetesClient, error) {
		return clients[kubeconfigPath], nil
	}

	p := newPlugin(newClientFunc)
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	bundle := getTestBundle(t)
	_, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "failed to apply ClusterTrustBundle for cluster \"test-cluster-2\": apply error")

	// The cluster that did not fail still got the bundle.
	require.Equal(t, 1, clients["/path/to/kubeconfig"].updateCount)
	require.Equal(t, 0, clients["/path/to/kubeconfig-2"].updateCount)

	// The failure must not record the bundle as published, so the same bundle
	// is applied again on the next call.
	clients["/path/to/kubeconfig-2"].applyErr = nil
	_, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.Equal(t, 2, clients["/path/to/kubeconfig"].updateCount)
	require.Equal(t, 1, clients["/path/to/kubeconfig-2"].updateCount)
	require.Equal(t, "example.org/spire", clients["/path/to/kubeconfig-2"].signerName)
	require.Empty(t, clients["/path/to/kubeconfig"].signerName)
}

func TestApplyClusterTrustBundle(t *testing.T) {
	hclConfig := `
		clusters = {
			"test-cluster" = {
				cluster_trust_bundle_name = "example.org:spire:bundle"
				signer_name = "example.org/spire"
				kubeconfig_path = "/path/to/kubeconfig"
			}
		}`

	ctbResources := func(groupVersion string) *metav1.APIResourceList {
		return &metav1.APIResourceList{
			GroupVersion: groupVersion,
			APIResources: []metav1.APIResource{{Name: "clustertrustbundles", Kind: "ClusterTrustBundle"}},
		}
	}

	for _, tt := range []struct {
		name         string
		resources    []*metav1.APIResourceList
		discoveryErr error
		expectMsg    string
		getCTB       func(context.Context, *fake.Clientset) (string, string, error)
	}{
		{
			name: "v1",
			resources: []*metav1.APIResourceList{
				ctbResources("certificates.k8s.io/v1"),
				ctbResources("certificates.k8s.io/v1beta1"),
			},
			getCTB: func(ctx context.Context, clientset *fake.Clientset) (string, string, error) {
				ctb, err := clientset.CertificatesV1().ClusterTrustBundles().Get(ctx, "example.org:spire:bundle", metav1.GetOptions{})
				if err != nil {
					return "", "", err
				}
				return ctb.Spec.SignerName, ctb.Spec.TrustBundle, nil
			},
		},
		{
			name: "v1beta1 when v1 is not served",
			resources: []*metav1.APIResourceList{
				{GroupVersion: "certificates.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "certificatesigningrequests"}}},
				ctbResources("certificates.k8s.io/v1beta1"),
			},
			getCTB: func(ctx context.Context, clientset *fake.Clientset) (string, string, error) {
				ctb, err := clientset.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, "example.org:spire:bundle", metav1.GetOptions{})
				if err != nil {
					return "", "", err
				}
				return ctb.Spec.SignerName, ctb.Spec.TrustBundle, nil
			},
		},
		{
			name: "not served",
			resources: []*metav1.APIResourceList{
				{GroupVersion: "certificates.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "certificatesigningrequests"}}},
			},
			expectMsg: "the API server does not serve ClusterTrustBundle in certificates.k8s.io/v1 or certificates.k8s.io/v1beta1",
		},
		{
			name:         "discovery error",
			discoveryErr: errors.New("connection refused"),
			expectMsg:    "failed to discover resources in certificates.k8s.io/v1: connection refused",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewClientset()
			clientset.Resources = tt.resources
			if tt.discoveryErr != nil {
				clientset.PrependReactor("get", "resource", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, tt.discoveryErr
				})
			}
			newClientFunc := func(kubeconfigPath string) (kubernetesClient, error) {
				return &k8sClient{clientset: clientset}, nil
			}

			var err error
			p := newPlugin(newClientFunc)
			plugintest.Load(t, builtin(p), nil,
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.Configure(hclConfig),
			)
			require.NoError(t, err)

			bundle := getTestBundle(t)
			_, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{
				Bundle: bundle,
			})
			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, codes.Internal, tt.expectMsg)
				return
			}
			require.NoError(t, err)

			signerName, trustBundle, err := tt.getCTB(t.Context(), clientset)
			require.NoError(t, err)
			require.Equal(t, "example.org/spire", signerName)
			require.Equal(t, []*x509.Certificate{parseCertificate(t, bundle.X509Authorities[0].Asn1)}, parsePEMCertificates(t, trustBundle))

			// A rotated bundle replaces the trust bundle of the existing object.
			cert2, _, err := util.LoadSVIDFixture()
			require.NoError(t, err)
			bundle = getTestBundle(t)
			bundle.X509Authorities = append(bundle.X509Authorities, &types.X509Certificate{Asn1: cert2.Raw})
			_, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{
				Bundle: bundle,
			})
			require.NoError(t, err)

			_, trustBundle, err = tt.getCTB(t.Context(), clientset)
			require.NoError(t, err)
			require.Len(t, parsePEMCertificates(t, trustBundle), 2)

			for _, action := range clientset.Actions() {
				if patch, ok := action.(k8stesting.PatchActionImpl); ok {
					opts := patch.GetPatchOptions()
					require.Equal(t, "spire-bundlepublisher-k8s_clustertrustbundle", opts.FieldManager)
					require.NotNil(t, opts.Force)
					require.True(t, *opts.Force)
				}
			}
		})
	}
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
		expectValid bool
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
							cluster_trust_bundle_name = "spire-bundle"
							kubeconfig_path = "/path/to/kubeconfig"
						}
					}`,
			},
			expectValid: true,
		},
		{
			name: "note about no clusters",
			req: &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: "example.org",
				},
			},
			expectValid: true,
			expectNotes: []string{"No clusters configured, bundle will not be published"},
		},
		{
			name: "name without signer name prefix",
			req: &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: "example.org",
				},
				HclConfiguration: `
					clusters = {
						"test-cluster" = {
							cluster_trust_bundle_name = "spire-bundle"
							signer_name = "example.org/spire"
						}
					}`,
			},
			expectNotes: []string{"cluster trust bundle name \"spire-bundle\" in cluster \"test-cluster\" must have the prefix \"example.org:spire:\" when signer_name is set"},
		},
		{
			name: "missing trust domain",
			req: &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{},
			},
			expectNotes: []string{
				"server core configuration must contain trust_domain",
				"No clusters configured, bundle will not be published",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Validate(t.Context(), tt.req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, tt.expectValid, resp.Valid)
			if tt.expectNotes != nil {
				require.Equal(t, tt.expectNotes, resp.Notes)
			}
		})
	}
}

type fakeClient struct {
	applyErr    error
	updateCount int
	signerName  string
	trustBundle []byte
}

func (c *fakeClient) ApplyClusterTrustBundle(ctx context.Context, cluster *Cluster, trustBundle []byte) error {
	if c.applyErr != nil {
		return c.applyErr
	}

	c.signerName = cluster.SignerName
	c.trustBundle = append([]byte(nil), trustBundle...)
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

func parseCertificate(t *testing.T, der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func parsePEMCertificates(t *testing.T, data string) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		require.Equal(t, "CERTIFICATE", block.Type)
		require.Empty(t, block.Headers)
		certs = append(certs, parseCertificate(t, block.Bytes))
	}
	require.Empty(t, rest)
	return certs
}
