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
				TrustAnchorName: "trust-anchor-name",
			},
		},
		{
			name: "no region",
			config: &Config{
				TrustAnchorName: "trust-anchor-name",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the region",
		},
		{
			name: "no trust anchor name",
			config: &Config{
				Region: "region",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "configuration is missing the trust anchor name",
		},
		{
			name: "client error",
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorName: "trust-anchor-name",
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
		createTrustAnchorErr error
		updateTrustAnchorErr error
		listTrustAnchorsErr  error
		listTrustAnchor      bool
	}{
		{
			name:   "success",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorName: "trust-anchor-name",
			},
			listTrustAnchor: true,
		},
		{
			name:   "multiple times",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorName: "trust-anchor-name",
			},
			listTrustAnchor: true,
		},
		{
			name:   "create trust anchor failure",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorName: "trust-anchor-name",
			},
			createTrustAnchorErr: errors.New("some error"),
			expectCode:           codes.Internal,
			expectMsg:            "failed to create trust anchor: some error",
		},
		{
			name:   "update trust anchor failure",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorName: "trust-anchor-name",
			},
			updateTrustAnchorErr: errors.New("some error"),
			expectCode:           codes.Internal,
			expectMsg:            "failed to update trust anchor: some error",
			listTrustAnchor:      true,
		},
		{
			name:   "list trust anchors failure",
			bundle: testBundle,
			config: &Config{
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
				Region:          "region",
				TrustAnchorName: "trust-anchor-name",
			},
			listTrustAnchorsErr: errors.New("some error"),
			expectCode:          codes.Internal,
			expectMsg:           "failed to list trust anchors: some error",
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
				TrustAnchorName: "trust-anchor-name",
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
					t:                     t,
					expectTrustAnchorName: aws.String(tt.config.TrustAnchorName),
					createTrustAnchorErr:  tt.createTrustAnchorErr,
					updateTrustAnchorErr:  tt.updateTrustAnchorErr,
					listTrustAnchorsErr:   tt.listTrustAnchorsErr,
				}
				if tt.listTrustAnchor {
					mockClient.trustAnchorName = aws.String(tt.config.TrustAnchorName)
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
		TrustAnchorName: "trust-anchor-name",
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
			t:                     t,
			expectTrustAnchorName: aws.String(config.TrustAnchorName),
		}, nil
	}
	p := newPlugin(newClient)
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	// Test multiple create/update trust anchor operations, and check that only a call
	// to CreateTrustAnchor/UpdateTrustAnchor is done when there is a modified bundle
	// that was not successfully published before.

	// Have an initial bundle with SequenceNumber = 1.
	bundle := getTestBundle(t)
	bundle.SequenceNumber = 1

	client, ok := p.rolesAnywhereClient.(*fakeClient)
	require.True(t, ok)

	// Reset the API call counters.
	client.createTrustAnchorCount = 0
	client.updateTrustAnchorCount = 0
	client.listTrustAnchorsCount = 0

	// Throw an error when calling CreateTrustAnchor.
	client.createTrustAnchorErr = errors.New("error calling CreateTrustAnchor")

	// Call PublishBundle. CreateTrustAnchor should be called and return an error.
	resp, err := p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.Error(t, err)
	require.Nil(t, resp)

	// Since the bundle could not be published, createTrustAnchorCount should be 0.
	require.Equal(t, 0, client.createTrustAnchorCount)
	require.Equal(t, 0, client.updateTrustAnchorCount)
	require.Equal(t, 5, client.listTrustAnchorsCount)

	// Remove the createTrustAnchorErr and try again.
	client.createTrustAnchorErr = nil
	client.listTrustAnchorsCount = 0
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, client.createTrustAnchorCount)
	require.Equal(t, 0, client.updateTrustAnchorCount)
	require.Equal(t, 5, client.listTrustAnchorsCount)

	// So that the client calls UpdateTrustAnchor from here on out
	client.trustAnchorName = &config.TrustAnchorName

	// Call PublishBundle with the same bundle.
	client.listTrustAnchorsCount = 0
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the counters should be the same as before.
	require.Equal(t, 1, client.createTrustAnchorCount)
	require.Equal(t, 0, client.updateTrustAnchorCount)
	require.Equal(t, 0, client.listTrustAnchorsCount)

	// Have a new bundle and call PublishBundle.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 3
	client.listTrustAnchorsCount = 0
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// PublishBundle was called with a different bundle, updateTrustAnchorCount should
	// be incremented to be 1.
	require.Equal(t, 1, client.createTrustAnchorCount)
	require.Equal(t, 1, client.updateTrustAnchorCount)
	require.Equal(t, 5, client.listTrustAnchorsCount)

	// Simulate that calling to UpdateTrustAnchor fails with an error.
	client.updateTrustAnchorErr = errors.New("error calling UpdateTrustAnchor")
	client.listTrustAnchorsCount = 0
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	// Since there is no change in the bundle, UpdateTrustAnchor should not be called
	// and there should be no error.
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The same bundle was used, the updateTrustAnchorCount counter should be still 1.
	require.Equal(t, 1, client.createTrustAnchorCount)
	require.Equal(t, 1, client.updateTrustAnchorCount)
	require.Equal(t, 0, client.listTrustAnchorsCount)

	// Have a new bundle and call PublishBundle. UpdateTrustAnchor should be called this
	// time and return an error.
	bundle = getTestBundle(t)
	bundle.SequenceNumber = 4
	client.listTrustAnchorsCount = 0
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})
	require.Error(t, err)
	require.Nil(t, resp)

	// Since the bundle could not be published, updateTrustAnchorCount should be
	// still 1.
	require.Equal(t, 1, client.createTrustAnchorCount)
	require.Equal(t, 1, client.updateTrustAnchorCount)
	require.Equal(t, 5, client.listTrustAnchorsCount)

	// Clear the UpdateTrustAnchor error and call PublishBundle.
	client.updateTrustAnchorErr = nil
	client.listTrustAnchorsCount = 0
	resp, err = p.PublishBundle(context.Background(), &bundlepublisherv1.PublishBundleRequest{
		Bundle: bundle,
	})

	// No error should happen this time.
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The updateTrustAnchorCount counter should be incremented to 2, since the bundle
	// should have been published successfully.
	require.Equal(t, 1, client.createTrustAnchorCount)
	require.Equal(t, 2, client.updateTrustAnchorCount)
	require.Equal(t, 5, client.listTrustAnchorsCount)
}

type fakeClient struct {
	t *testing.T

	awsConfig              aws.Config
	createTrustAnchorErr   error
	createTrustAnchorCount int
	updateTrustAnchorErr   error
	updateTrustAnchorCount int
	listTrustAnchorsErr    error
	listTrustAnchorsCount  int
	trustAnchorName        *string

	expectTrustAnchorName *string
}

func (c *fakeClient) CreateTrustAnchor(_ context.Context, params *rolesanywhere.CreateTrustAnchorInput, _ ...func(*rolesanywhere.Options)) (*rolesanywhere.CreateTrustAnchorOutput, error) {
	if c.createTrustAnchorErr != nil {
		return nil, c.createTrustAnchorErr
	}

	require.Equal(c.t, c.expectTrustAnchorName, params.Name, "trust anchor name mismatch")
	c.createTrustAnchorCount++
	trustAnchorArn := "trustAnchorArn"
	return &rolesanywhere.CreateTrustAnchorOutput{
		TrustAnchor: &rolesanywheretypes.TrustAnchorDetail{
			TrustAnchorArn: &trustAnchorArn,
		},
	}, nil
}

func (c *fakeClient) UpdateTrustAnchor(_ context.Context, params *rolesanywhere.UpdateTrustAnchorInput, _ ...func(*rolesanywhere.Options)) (*rolesanywhere.UpdateTrustAnchorOutput, error) {
	if c.updateTrustAnchorErr != nil {
		return nil, c.updateTrustAnchorErr
	}

	c.updateTrustAnchorCount++
	trustAnchorArn := "trustAnchorArn"
	return &rolesanywhere.UpdateTrustAnchorOutput{
		TrustAnchor: &rolesanywheretypes.TrustAnchorDetail{
			TrustAnchorArn: &trustAnchorArn,
		},
	}, nil
}

func (c *fakeClient) ListTrustAnchors(_ context.Context, params *rolesanywhere.ListTrustAnchorsInput, _ ...func(*rolesanywhere.Options)) (*rolesanywhere.ListTrustAnchorsOutput, error) {
	if c.listTrustAnchorsErr != nil {
		return nil, c.listTrustAnchorsErr
	}

	c.listTrustAnchorsCount++
	if c.listTrustAnchorsCount == 5 {
		listTrustAnchorsOutput := rolesanywhere.ListTrustAnchorsOutput{}
		if c.trustAnchorName != nil {
			listTrustAnchorsOutput.TrustAnchors = []rolesanywheretypes.TrustAnchorDetail{
				rolesanywheretypes.TrustAnchorDetail{
					Name: c.trustAnchorName,
				},
			}
		}
		return &listTrustAnchorsOutput, nil
	} else {
		nextToken := "next-token"
		return &rolesanywhere.ListTrustAnchorsOutput{
			NextToken: &nextToken,
		}, nil
	}
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
