package awsrolesanywhere

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	rolesanywheretypes "github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
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
		expectCode       codes.Code
		expectMsg        string
		config           *Config
		expectAWSConfig  *aws.Config
	}{
		{
			name: "success",
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorID:   "trust-anchor-id",
			},
		},
		{
			name: "no region",
			config: &Config{
				TrustAnchorID: "trust-anchor-id",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the region",
		},
		{
			name: "no trust anchor id",
			config: &Config{
				Region: "region",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the trust anchor id",
		},
		{
			name: "client error",
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorID:   "trust-anchor-id",
			},
			expectCode:   codes.Internal,
			expectMsg:    "failed to create client: client creation error",
			newClientErr: errors.New("client creation error"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(tt.config),
			}

			newClient := func(awsConfig aws.Config) (rolesAnywhere, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return &fakeClient{
					awsConfig: awsConfig,
				}, nil
			}
			p := newPlugin(newClient)

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)

			if tt.expectMsg != "" {
				require.Nil(t, p.config)
				return
			}

			// Check that the plugin has the expected configuration.
			require.Equal(t, tt.config, p.config)

			client, ok := p.rolesAnywhereClient.(*fakeClient)
			require.True(t, ok)

			// It's important to check that the configuration has been wired
			// up to the aws config, that needs to have the specified region
			// and credentials.
			require.Equal(t, tt.config.Region, client.awsConfig.Region)
			creds, err := client.awsConfig.Credentials.Retrieve(context.Background())
			require.NoError(t, err)
			require.Equal(t, tt.config.AccessKeyID, creds.AccessKeyID)
			require.Equal(t, tt.config.SecretAccessKey, creds.SecretAccessKey)
		})
	}
}

func TestPublishBundle(t *testing.T) {
	testBundle := getTestBundle(t)

	for _, tt := range []struct {
		name string

		newClientErr         error
		expectCode           codes.Code
		expectMsg            string
		config               *Config
		bundle               *types.Bundle
		updateTrustAnchorErr error
	}{
		{
			name:   "success",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorID:   "trust-anchor-id",
			},
		},
		{
			name:   "multiple times",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorID:   "trust-anchor-id",
			},
		},
		{
			name:   "update trust anchor failure",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorID:   "trust-anchor-id",
			},
			updateTrustAnchorErr: errors.New("some error"),
			expectCode:           codes.Internal,
			expectMsg:            "failed to update trust anchor: some error",
		},
		{
			name:       "not configured",
			expectCode: codes.FailedPrecondition,
			expectMsg:  "not configured",
		},
		{
			name: "missing bundle",
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorID:   "trust-anchor-id",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing bundle in request",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(tt.config),
			}

			newClient := func(awsConfig aws.Config) (rolesAnywhere, error) {
				mockClient := fakeClient{
					t:                    t,
					expectTrustAnchorID:  aws.String(tt.config.TrustAnchorID),
					updateTrustAnchorErr: tt.updateTrustAnchorErr,
				}
				return &mockClient, nil
			}
			p := newPlugin(newClient)

			if tt.config != nil {
				plugintest.Load(t, builtin(p), nil, options...)
				require.NoError(t, err)
			}

			resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
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
	config := &Config{
		AccessKeyID:     "access-key-id",
		SecretAccessKey: "secret-access-key",
		Region:          "region",
		TrustAnchorID:   "trust-anchor-id",
	}

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.ConfigureJSON(config),
	}

	newClient := func(awsConfig aws.Config) (rolesAnywhere, error) {
		return &fakeClient{
			t:                   t,
			expectTrustAnchorID: aws.String(config.TrustAnchorID),
		}, nil
	}
	p := newPlugin(newClient)
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	// Test multiple update trust anchor operations, and check that only a call to
	// UpdateTrustAnchor is made when there is a modified bundle that was not successfully
	// published before.

	// Have an initial bundle with SequenceNumber = 1.
	bundle := getTestBundle(t)
	bundle.SequenceNumber = 1

	client, ok := p.rolesAnywhereClient.(*fakeClient)
	require.True(t, ok)

	// Reset the API call counters.
	client.updateTrustAnchorCount = 0

	// Throw an error when calling UpdateTrustAnchor.
	client.updateTrustAnchorErr = errors.New("error calling UpdateTrustAnchor")

	// Call PublishBundle. UpdateTrustAnchor should be called and return an error.
	resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.Error(t, err)
	require.Nil(t, resp)

	// The UpdateTrustAnchor call failed, so its counter should not be incremented.
	require.Equal(t, 0, client.updateTrustAnchorCount)

	// Remove the updateTrustAnchorErr and try again.
	client.updateTrustAnchorErr = nil
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, client.updateTrustAnchorCount)

	// Call PublishBundle with the same bundle.
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the counter should be the same as before.
	require.Equal(t, 1, client.updateTrustAnchorCount)

	// Have a new bundle and call PublishBundle.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 2
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// PublishBundle was called with a different bundle, updateTrustAnchorCount should
	// be incremented to be 3.
	require.Equal(t, 2, client.updateTrustAnchorCount)

	// Try to publish a bundle that's too large, and expect that we receive an error.
	bundle = getLargeTestBundle(t)
	bundle.SequenceNumber = 3
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.Nil(t, resp)
	require.Error(t, err)
}

type fakeClient struct {
	t *testing.T

	awsConfig              aws.Config
	updateTrustAnchorErr   error
	updateTrustAnchorCount int

	expectTrustAnchorID *string
}

func (c *fakeClient) UpdateTrustAnchor(_ context.Context, params *rolesanywhere.UpdateTrustAnchorInput, _ ...func(*rolesanywhere.Options)) (*rolesanywhere.UpdateTrustAnchorOutput, error) {
	if c.updateTrustAnchorErr != nil {
		return nil, c.updateTrustAnchorErr
	}

	require.Equal(c.t, c.expectTrustAnchorID, params.TrustAnchorId, "trust anchor id mismatch")
	trustAnchorArn := "trustAnchorArn"
	trustAnchorName := "trustAnchorName"
	c.updateTrustAnchorCount++
	return &rolesanywhere.UpdateTrustAnchorOutput{
		TrustAnchor: &rolesanywheretypes.TrustAnchorDetail{
			TrustAnchorArn: &trustAnchorArn,
			Name:           &trustAnchorName,
		},
	}, nil
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

func getLargeTestBundle(t *testing.T) *types.Bundle {
	largeBundle, err := util.LoadLargeBundleFixture()
	require.NoError(t, err)

	return &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: largeBundle[0].Raw}},
		JwtAuthorities:  []*types.JWTKey{},
		RefreshHint:     1440,
		SequenceNumber:  101,
	}
}
